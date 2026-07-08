package gpgaegishttp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/gofiber/fiber/v2"
)

// Config defines the config for middleware.
type Config struct {
	// Next defines a function to skip this middleware when returned true.
	Next func(c *fiber.Ctx) bool

	// RequireKeyserver checks the Ubuntu Keyserver for the user's public key instead of trusting the client payload
	RequireKeyserver bool
	// CheckRevocation blocks authentication if the GPG key is revoked
	CheckRevocation bool
	// MinApproveCount enforces Web of Trust signatures (excluding self-signatures)
	MinApproveCount int

	// EncryptResponses will encrypt all outgoing payloads matching x-gpg-id with the user's public key
	EncryptResponses bool

	// ChallengePath is the route that returns the random challenge string to the frontend
	ChallengePath string
	// LoginPath is the route where the frontened submits the challenge signature
	LoginPath string

	// Server Identity settings for E2E
	ServerEmail          string
	ServerPassphrase     string
	ServerPrivateKeyPath string
	ServerPublicKeyPath  string
	DecryptRequests      bool
	TunnelingEnabled     bool

	// Custom Auth hook: If provided, the middleware calls this to validate the user and retrieve their public key
	// Takes precedence over Ubuntu Keyservers
	GpgIdCheck func(email string) (publicKey string, err error)
	// KeyCacheDuration defines how long a resolved public key will be cached in memory. Default: 60s
	KeyCacheDuration time.Duration

	// AllowedKeysApi makes a GET request to api/{fingerprint} and expects {"allowed":true}
	AllowedKeysApi string
}

// ConfigDefault is the default config
var ConfigDefault = Config{
	Next:             nil,
	RequireKeyserver: true,
	CheckRevocation:  true,
	MinApproveCount:  1,
	EncryptResponses: true,
	ChallengePath:        "/api/challenge",
	LoginPath:            "/api/login",
	ServerEmail:          "",
	ServerPassphrase:     "",
	ServerPrivateKeyPath: "server_private.asc",
	ServerPublicKeyPath:  "server_public.asc",
	DecryptRequests:      false,
	TunnelingEnabled:     true,
	GpgIdCheck:           nil,
	KeyCacheDuration:     60 * time.Second,
	AllowedKeysApi:       "",
}

// Helper function to set default values
func configDefault(config ...Config) Config {
	if len(config) < 1 {
		return ConfigDefault
	}
	cfg := config[0]

	if cfg.ChallengePath == "" {
		cfg.ChallengePath = ConfigDefault.ChallengePath
	}
	if cfg.LoginPath == "" {
		cfg.LoginPath = ConfigDefault.LoginPath
	}
	if cfg.ServerPrivateKeyPath == "" {
		cfg.ServerPrivateKeyPath = ConfigDefault.ServerPrivateKeyPath
	}
	if cfg.ServerPublicKeyPath == "" {
		cfg.ServerPublicKeyPath = ConfigDefault.ServerPublicKeyPath
	}
	if cfg.KeyCacheDuration == 0 {
		cfg.KeyCacheDuration = ConfigDefault.KeyCacheDuration
	}
	return cfg
}

func generateChallenge() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func zbase32Encode(data []byte) string {
	alphabet := "ybndrfg8ejkmcpqxot1uwisza345h769"
	var bits string
	for _, b := range data {
		bits += fmt.Sprintf("%08b", b)
	}
	var encoded string
	for i := 0; i < len(bits); i += 5 {
		chunk := bits[i:]
		if len(chunk) > 5 {
			chunk = chunk[:5]
		} else {
			// pad with 0
			for len(chunk) < 5 {
				chunk += "0"
			}
		}
		num, _ := strconv.ParseInt(chunk, 2, 64)
		encoded += string(alphabet[num])
	}
	return encoded
}

func fetchFromWKD(email string) (openpgp.EntityList, error) {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid email")
	}
	localPart := strings.ToLower(parts[0])
	domain := strings.ToLower(parts[1])

	h := sha1.New()
	h.Write([]byte(localPart))
	hash := zbase32Encode(h.Sum(nil))

	url := fmt.Sprintf("https://%s/.well-known/openpgpkey/hu/%s?l=%s", domain, hash, localPart)
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("WKD not found")
	}

	// WKD responses are strictly binary (not armored).
	return openpgp.ReadKeyRing(resp.Body)
}

// LoginRequest is the JSON payload structure from the frontend
type LoginRequest struct {
	Email     string `json:"email"`
	Challenge string `json:"challenge"`
	Signature string `json:"signature"`
	PublicKey string `json:"public_key"`
}

// Shared memory cache for validated Public Keys
type pubKeyCacheEntry struct {
	EntityList openpgp.EntityList
	ExpiresAt  time.Time
}

var (
	PublicKeyCache = make(map[string]pubKeyCacheEntry)
	nonceCache     sync.Map
	nonceCleanup   sync.Once
)

// New creates a new middleware handler
func New(config ...Config) fiber.Handler {
	cfg := configDefault(config...)
	activeChallenges := make(map[string]bool)

	// Idempotency GC
	nonceCleanup.Do(func() {
		go func() {
			for {
				time.Sleep(1 * time.Minute)
				now := time.Now().UnixNano() / 1e6
				nonceCache.Range(func(key, value interface{}) bool {
					if now-value.(int64) > 60000 {
						nonceCache.Delete(key)
					}
					return true
				})
			}
		}()
	})

	var serverEntity *openpgp.Entity

	if cfg.DecryptRequests {
		if cfg.ServerEmail == "" {
			log.Fatal("DecryptRequests is true but ServerEmail is empty. Cannot use server keys.")
		}

		if cfg.ServerPassphrase == "" {
			fmt.Printf("\n🔒 Please enter the Server GPG Passphrase for %s (will be used for generation or unlocking): ", cfg.ServerEmail)
			var p string
			fmt.Scanln(&p)
			cfg.ServerPassphrase = strings.TrimSpace(p)
		}

		if _, err := os.Stat(cfg.ServerPrivateKeyPath); os.IsNotExist(err) {
			log.Println("Generating new Server GPG KeyPair...")
			serverEntity, err = generateServerKey(cfg.ServerEmail, cfg.ServerPassphrase, cfg.ServerPrivateKeyPath, cfg.ServerPublicKeyPath)
			if err != nil {
				log.Fatal(err)
			}
			
			log.Println("Uploading new public key to Ubuntu Keyserver...")
			err = uploadKeyToKeyserver(serverEntity)
			if err != nil {
				log.Printf("⚠️ Failed to upload to keyserver: %v", err)
			} else {
				log.Println("✅ Successfully uploaded to keyserver.")
			}
		} else {
			log.Println("Loading existing Server GPG KeyPair from " + cfg.ServerPrivateKeyPath + " ...")
			serverEntity, err = loadServerKey(cfg.ServerPassphrase, cfg.ServerPrivateKeyPath)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	return func(c *fiber.Ctx) error {
		// Server Public Key Publisher
		if c.Path() == "/api/server-pubkey" && c.Method() == fiber.MethodGet && cfg.DecryptRequests {
			buf := new(bytes.Buffer)
			w, _ := armor.Encode(buf, openpgp.PublicKeyType, nil)
			serverEntity.Serialize(w)
			w.Close()
			c.Set("Content-Type", "text/plain")
			c.Set("x-gpg-server-id", cfg.ServerEmail) // Advertise ID
			return c.SendString(buf.String())
		}

		// Inject support flag transparently
		c.Set("x-gpg-support", "true")
		if cfg.DecryptRequests && cfg.ServerEmail != "" {
			c.Set("x-gpg-server-id", cfg.ServerEmail)
		}

		// Check if request is Encrypted and intercept
		if cfg.DecryptRequests && c.Get("x-gpg-encrypted") != "" {
			body := c.Body()
			block, err := armor.Decode(bytes.NewReader(body))
			if err == nil && block.Type == "PGP MESSAGE" {
				md, err := openpgp.ReadMessage(block.Body, openpgp.EntityList{serverEntity}, nil, nil)
				if err == nil {
					decryptedBody, err := io.ReadAll(md.UnverifiedBody)
					if err == nil {
						var parsed map[string]interface{}
						if errUnmarshal := json.Unmarshal(decryptedBody, &parsed); errUnmarshal == nil {
							if tsVal, ok := parsed["_gpg_timestamp"].(float64); ok {
								if nonce, ok := parsed["_gpg_nonce"].(string); ok {
									now := float64(time.Now().UnixNano()) / 1e6
									if now-tsVal > 60000 || tsVal-now > 60000 {
										return c.Status(403).JSON(fiber.Map{"error": "Payload expired or timestamp invalid. Replay Attack Prevented."})
									}
									if _, loaded := nonceCache.LoadOrStore(nonce, int64(now)); loaded {
										return c.Status(403).JSON(fiber.Map{"error": "Duplicate payload detected. Replay Attack Prevented."})
									}
									delete(parsed, "_gpg_timestamp")
									delete(parsed, "_gpg_nonce")
									decryptedBody, _ = json.Marshal(parsed)
								}
							}
						}

						if c.Get("x-gpg-tunnel") == "true" {
							var tunnel struct {
								Method  string            `json:"tunnel_method"`
								Url     string            `json:"tunnel_url"`
								Headers map[string]string `json:"tunnel_headers"`
								Body    interface{}       `json:"tunnel_body"`
							}
							if json.Unmarshal(decryptedBody, &tunnel) == nil {
								c.Request().Header.SetMethod(tunnel.Method)
								c.Request().SetRequestURI(tunnel.Url)
								for k, v := range tunnel.Headers {
									c.Request().Header.Set(k, v)
								}
								if tunnel.Body != nil {
									bodyBytes, _ := json.Marshal(tunnel.Body)
									c.Request().SetBody(bodyBytes)
								} else {
									c.Request().SetBody([]byte{})
								}
							}
						} else {
							c.Request().SetBody(decryptedBody)
						}
					}
				} else {
					return c.Status(400).JSON(fiber.Map{"error": "Failed to decrypt client request payload: " + err.Error()})
				}
			}
		}

		// Don't execute middleware logic if Next returns true
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		// Inject support flag transparently
		c.Set("x-gpg-support", "true")
		if cfg.TunnelingEnabled {
			c.Set("x-gpg-tunneling", "true")
		} else {
			c.Set("x-gpg-tunneling", "false")
		}

		// Handle Challenge Request
		if c.Path() == cfg.ChallengePath && c.Method() == fiber.MethodGet {
			challenge := generateChallenge()
			activeChallenges[challenge] = true
			return c.JSON(fiber.Map{"challenge": challenge})
		}

		// Handle Login Request
		if c.Path() == cfg.LoginPath && c.Method() == fiber.MethodPost {
			var req LoginRequest
			if err := c.BodyParser(&req); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": "Invalid request payload"})
			}
			if !activeChallenges[req.Challenge] {
				return c.Status(400).JSON(fiber.Map{"error": "Invalid or expired challenge"})
			}

			block, _ := clearsign.Decode([]byte(req.Signature))
			if block == nil {
				return c.Status(400).JSON(fiber.Map{"error": "Failed to decode clear signature"})
			}
			if string(block.Bytes) != req.Challenge {
				return c.Status(400).JSON(fiber.Map{"error": "Signature does not cover the exact challenge string"})
			}

			var keyring openpgp.EntityList
			var err error

			if cached, ok := PublicKeyCache[req.Email]; ok && time.Now().Before(cached.ExpiresAt) {
				keyring = cached.EntityList
			} else if cfg.GpgIdCheck != nil {
				pubKeyStr, errCheck := cfg.GpgIdCheck(req.Email)
				if errCheck != nil {
					return c.Status(401).JSON(fiber.Map{"error": "User validation failed: " + errCheck.Error()})
				}
				keyring, err = openpgp.ReadArmoredKeyRing(bytes.NewBufferString(pubKeyStr))
				if err != nil || len(keyring) == 0 {
					return c.Status(400).JSON(fiber.Map{"error": "Invalid armored public key returned by GpgIdCheck."})
				}
			} else if cfg.RequireKeyserver {
				// Dual-Verification: Authoritative Domain WKD primary, Keyserver fallback
				keyring, err = fetchFromWKD(req.Email)
				if err != nil || len(keyring) == 0 {
					keyserverURL := "http://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=" + url.QueryEscape(req.Email)
					resp, errHttp := http.Get(keyserverURL)
					if errHttp != nil {
						return c.Status(500).JSON(fiber.Map{"error": "Failed to connect to WKD and fallback PGP Keyserver: " + errHttp.Error()})
					}
					defer resp.Body.Close()

					if resp.StatusCode != http.StatusOK {
						return c.Status(400).JSON(fiber.Map{"error": "Public key not found on WKD or Keyserver for this email. Ensure your key is published!"})
					}

					keyring, err = openpgp.ReadArmoredKeyRing(resp.Body)
				}

				if err != nil || len(keyring) == 0 {
					return c.Status(400).JSON(fiber.Map{"error": "Failed to parse public keys from WKD and Keyserver."})
				}
			} else {
				keyring, err = openpgp.ReadArmoredKeyRing(bytes.NewBufferString(req.PublicKey))
				if err != nil || len(keyring) == 0 {
					return c.Status(400).JSON(fiber.Map{"error": "Invalid armored public key provided."})
				}
			}

			signer, err := openpgp.CheckDetachedSignature(keyring, bytes.NewBuffer(block.Bytes), block.ArmoredSignature.Body, nil)
			if err != nil {
				return c.Status(401).JSON(fiber.Map{"error": "Invalid signature: " + err.Error()})
			}

			emailMatched := false
			var matchedIdentity *openpgp.Identity

			for _, ident := range signer.Identities {
				if ident.UserId.Email == req.Email {
					emailMatched = true
					matchedIdentity = ident
					break
				}
			}

			if !emailMatched {
				return c.Status(401).JSON(fiber.Map{"error": "Signature valid, but email does not match the key identity"})
			}

			if cfg.CheckRevocation {
				if len(signer.Revocations) > 0 {
					return c.Status(401).JSON(fiber.Map{"error": "The GPG key has been revoked by the owner."})
				}
			}

			if cfg.MinApproveCount > 0 {
				approveCount := 0
				for _, sig := range matchedIdentity.Signatures {
					// We consider approvals to be signatures issued by a different key
					if sig.IssuerKeyId != nil && *sig.IssuerKeyId != signer.PrimaryKey.KeyId {
						approveCount++
					}
				}
				if approveCount < cfg.MinApproveCount {
					return c.Status(401).JSON(fiber.Map{"error": "GPG key lacks sufficient Web of Trust approvals. Not enough third-party signatures."})
				}
			}

			if cfg.AllowedKeysApi != "" {
				fingerprint := fmt.Sprintf("%X", signer.PrimaryKey.Fingerprint)
				apiURL := strings.TrimRight(cfg.AllowedKeysApi, "/") + "/" + fingerprint
				client := &http.Client{Timeout: 5 * time.Second}
				
				resp, errAPI := client.Get(apiURL)
				if errAPI != nil || resp.StatusCode != http.StatusOK {
					return c.Status(401).JSON(fiber.Map{"error": "Failed to verify key authorization"})
				}
				defer resp.Body.Close()
				
				var allowedResp struct {
					Allowed bool `json:"allowed"`
				}
				if errDecode := json.NewDecoder(resp.Body).Decode(&allowedResp); errDecode != nil {
					return c.Status(500).JSON(fiber.Map{"error": "Invalid response from allowed keys API"})
				}
				if !allowedResp.Allowed {
					return c.Status(401).JSON(fiber.Map{"error": "This GPG key is not authorized to login"})
				}
			}

			// Signature verified, identity verified. Discard the challenge to prevent replay attacks
			delete(activeChallenges, req.Challenge)

			// Store ONLY the validated signer entity in the cache to avoid encrypting to old/invalid keys returned from the keyserver
			PublicKeyCache[req.Email] = pubKeyCacheEntry{
				EntityList: openpgp.EntityList{signer},
				ExpiresAt:  time.Now().Add(cfg.KeyCacheDuration),
			}

			return c.JSON(fiber.Map{
				"status":  "success",
				"message": "Successfully authenticated via GPG Aegis Http!",
				"email":   req.Email,
			})
		}

		// If End-to-End Encryption is enabled and the client specifies its GPG ID
		if cfg.EncryptResponses {
			fmt.Println("Encrypt body")
			if gpgID := c.Get("x-gpg-id"); gpgID != "" {
				fmt.Println("Encrypt body for user", gpgID)
				if cached, ok := PublicKeyCache[gpgID]; ok && time.Now().Before(cached.ExpiresAt) {
					keyring := cached.EntityList
					fmt.Println("Encrypt body for user", gpgID)
					// Wait for downstream handlers to finish generating the response
					err := c.Next()
					if err != nil {
						return err
					}

					// Encrypt the plain-text response body using the user's public key
					buf := new(bytes.Buffer)
					armoredWriter, err := armor.Encode(buf, "PGP MESSAGE", nil)
					if err == nil {
						plaintextWriter, err := openpgp.Encrypt(armoredWriter, keyring, nil, nil, nil)
						if err == nil {
							plaintextWriter.Write(c.Response().Body())
							plaintextWriter.Close()
							armoredWriter.Close()

							// Replace the plain body with the armored ciphertext
							c.Response().SetBodyRaw(buf.Bytes())
							c.Set("x-gpg-encrypted", gpgID)
						} else {
							log.Println("Failed to encrypt response for user", gpgID, err)
						}
					} else {
						log.Println("Failed to encrypt response for user", gpgID, err)
					}
					return nil
				}
			}
		}

		// Continue to the next handler for non-auth paths
		return c.Next()
	}
}

// Generate an RSA 4096 Keypair and serialize to files
func generateServerKey(email, passphrase, privPath, pubPath string) (*openpgp.Entity, error) {
	config := &packet.Config{
		DefaultHash:   crypto.SHA256,
		DefaultCipher: packet.CipherAES256,
	}
	entity, err := openpgp.NewEntity("Aegis Http Server", "Backend API", email, config)
	if err != nil {
		return nil, err
	}

	if passphrase != "" {
		err = entity.PrivateKey.Encrypt([]byte(passphrase))
		if err != nil {
			return nil, err
		}
		for _, subkey := range entity.Subkeys {
			err = subkey.PrivateKey.Encrypt([]byte(passphrase))
			if err != nil {
				return nil, err
			}
		}
	}

	privFile, err := os.Create(privPath)
	if err == nil {
		defer privFile.Close()
		w, _ := armor.Encode(privFile, openpgp.PrivateKeyType, nil)
		entity.SerializePrivateWithoutSigning(w, config)
		w.Close()
	}

	pubFile, err := os.Create(pubPath)
	if err == nil {
		defer pubFile.Close()
		w, _ := armor.Encode(pubFile, openpgp.PublicKeyType, nil)
		entity.Serialize(w)
		w.Close()
	}

	return entity, nil
}

// Load Server Keys and unlock the private key into memory
func loadServerKey(passphrase, privPath string) (*openpgp.Entity, error) {
	f, err := os.Open(privPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	entityList, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil || len(entityList) == 0 {
		return nil, fmt.Errorf("failed to read server private key")
	}
	entity := entityList[0]

	if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
		if passphrase == "" {
			fmt.Printf("\n🔒 Server Private Key is encrypted. Enter passphrase for %s: ", emailKeyDisplay(entity))
			var p string
			fmt.Scanln(&p)
			passphrase = strings.TrimSpace(p)
		}
		err = entity.PrivateKey.Decrypt([]byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt primary key: %v", err)
		}
		for _, subkey := range entity.Subkeys {
			if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
				subkey.PrivateKey.Decrypt([]byte(passphrase))
			}
		}
	}

	return entity, nil
}


func emailKeyDisplay(e *openpgp.Entity) string {
	for name := range e.Identities {
		return name
	}
	return "Server Key"
}

// Helper to upload key
func uploadKeyToKeyserver(entity *openpgp.Entity) error {
	buf := new(bytes.Buffer)
	w, _ := armor.Encode(buf, openpgp.PublicKeyType, nil)
	entity.Serialize(w)
	w.Close()

	data := url.Values{}
	data.Set("keytext", buf.String())

	resp, err := http.PostForm("http://keyserver.ubuntu.com/pks/add", data)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("keyserver returned status: %d", resp.StatusCode)
	}

	return nil
}
