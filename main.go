package main

import (
	"fmt"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/aegis-http/backend/gpgaegishttp"
)

func main() {
	app := fiber.New()

	// CORS setup so the Vue app can call it
	app.Use(cors.New(cors.Config{
		AllowOrigins:  "http://localhost:5173, http://localhost:5174, http://localhost:8000", // Vue, React, and Vanilla Python dev servers
		AllowHeaders:  "Origin, Content-Type, Accept, x-gpg-id, x-gpg-signature, x-gpg-encrypted, x-gpg-tunnel, x-gpg-session-token",
		ExposeHeaders: "x-gpg-server-id, x-gpg-support, x-gpg-tunneling, x-gpg-encrypted",
	}))

	// Register our reusable GPG Aegis Http Middleware just like a normal Fiber extension!
	app.Use(gpgaegishttp.New(gpgaegishttp.Config{
		RequireKeyserver: false, // Set to false to use the client-provided key in case Keyserver is stale/missing subkeys
		CheckRevocation:  true,  // Check if key is revoked
		EncryptResponses: true,
		MinApproveCount:  0, // Minimum Web of Trust counts
		ServerEmail:      "server@aegishttpgpg.local",
		ServerPassphrase: "", // Prompt at boot
		DecryptRequests:  true,
	}))

	// Protected home route
	app.Get("/api/protected", func(c *fiber.Ctx) error {
		email := c.Get("x-gpg-id")
		return c.JSON(fiber.Map{
			"status":  "success",
			"message": fmt.Sprintf("Welcome to the secret vault, %s!", email),
			"data":    "Top secret information here",
			"headers": c.GetReqHeaders(),
		})
	})

	app.Post("/api/protected", func(c *fiber.Ctx) error {
		email := c.Get("x-gpg-id")

		var body map[string]interface{}
		if err := c.BodyParser(&body); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Failed to parse body - was it decrypted properly?", "raw": string(c.Body())})
		}

		return c.JSON(fiber.Map{
			"status":        "success",
			"message":       fmt.Sprintf("Received top secret POST from %s!", email),
			"received_body": body,
			"headers":       c.GetReqHeaders(),
		})
	})

	log.Println("Starting GoFiber GPG Aegis Http Backend on :3003")
	app.Listen(":3003")
}
