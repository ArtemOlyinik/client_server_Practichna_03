package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	log.SetFlags(0)
	log.Println("=== Агент диспетчеризації (mTLS Client) ===")

	certDir := env("CERT_DIR", "certs")
	serverAddr := env("SERVER_ADDR", "127.0.0.1:8443")

	clientCert, err := tls.LoadX509KeyPair(
		filepath.Join(certDir, "client.crt"),
		filepath.Join(certDir, "client.key"),
	)
	if err != nil {
		log.Fatalf("[КЛІЄНТ] Не вдалося завантажити сертифікат клієнта: %v", err)
	}

	if len(clientCert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(clientCert.Certificate[0])
		if err == nil {
			log.Printf("[КЛІЄНТ] Завантажено сертифікат клієнта: client.crt (CN=%s)", leaf.Subject.CommonName)
		}
	}

	caPEM, err := os.ReadFile(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		log.Fatalf("[КЛІЄНТ] Не вдалося прочитати ca.crt: %v", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		log.Fatal("[КЛІЄНТ] Не вдалося завантажити Root CA")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}

	log.Printf("[КЛІЄНТ] Підключення до шлюзу %s...", serverAddr)
	conn, err := tls.Dial("tcp", serverAddr, tlsConfig)
	if err != nil {
		log.Fatalf("[КЛІЄНТ] Помилка mTLS-підключення: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	log.Printf("[КЛІЄНТ] mTLS-рукостискання успішне. Використано протокол %s", tls.VersionName(state.Version))

	message := "CRITICAL_ERROR: Database connection timeout on node-04"
	log.Printf("[КЛІЄНТ] Відправка алерту: %s", message)

	if _, err := fmt.Fprintf(conn, "%s\n", message); err != nil {
		log.Fatalf("[КЛІЄНТ] Не вдалося надіслати алерт: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if strings.TrimSpace(line) != "" {
			log.Printf("[КЛІЄНТ] Відповідь від сервера: %s", strings.TrimSpace(line))
		}
		if err != nil {
			break
		}
	}

	log.Println("[КЛІЄНТ] Сесію успішно завершено.")
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
