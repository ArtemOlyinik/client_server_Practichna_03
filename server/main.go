package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArtemOlyinik/client_server_Practichna_03/internal/email"
)

func main() {
	log.SetFlags(0)
	log.Println("=== Захищений шлюз критичних сповіщень (mTLS: 8443, SMTP Target: 1025) ===")

	listenAddr := env("LISTEN_ADDR", ":8443")
	smtpAddr := env("SMTP_ADDR", "127.0.0.1:1025")
	mailFrom := env("MAIL_FROM", "gateway@internal.net")
	mailTo := env("MAIL_TO", "duty-engineer@internal.net")
	certDir := env("CERT_DIR", "certs")

	serverCert, err := tls.LoadX509KeyPair(
		filepath.Join(certDir, "server.crt"),
		filepath.Join(certDir, "server.key"),
	)
	if err != nil {
		log.Fatalf("[СЕРВЕР] Не вдалося завантажити сертифікат сервера: %v", err)
	}

	caPEM, err := os.ReadFile(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		log.Fatalf("[СЕРВЕР] Не вдалося прочитати ca.crt: %v", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		log.Fatal("[СЕРВЕР] Не вдалося завантажити жодного сертифіката з ca.crt")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
	}

	listener, err := tls.Listen("tcp", listenAddr, tlsConfig)
	if err != nil {
		log.Fatalf("[СЕРВЕР] Не вдалося відкрити mTLS-слухач: %v", err)
	}
	defer listener.Close()

	log.Printf("[СЕРВЕР] Пул CA завантажено: ca.crt (1 сертифікат)")
	log.Printf("[СЕРВЕР] Слухач mTLS відкрито на порту %s", listener.Addr())

	mailConfig := email.Config{
		Address: smtpAddr,
		From:    mailFrom,
		To:      []string{mailTo},
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[СЕРВЕР] Помилка приймання з'єднання: %v", err)
			continue
		}
		go handleConnection(conn, mailConfig)
	}
}

func handleConnection(conn net.Conn, mailConfig email.Config) {
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		log.Printf("[СЕРВЕР] Неочікуваний тип з'єднання від %s", conn.RemoteAddr())
		return
	}

	_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[БЕЗПЕКА] Відхилено з'єднання від %s: %v", conn.RemoteAddr(), err)
		return
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		log.Printf("[БЕЗПЕКА] Клієнт %s не надав сертифікат", conn.RemoteAddr())
		return
	}

	peer := state.PeerCertificates[0]
	log.Printf("[ПІДКЛЮЧЕННЯ] Встановлено TLS-з'єднання від %s", conn.RemoteAddr())
	log.Printf("[АУДИТ ZERO TRUST] Клієнт верифікований: CN=%s, Серійний номер=%s",
		peer.Subject.CommonName,
		peer.SerialNumber.String(),
	)
	log.Printf("[АУДИТ] Протокол: %s, сертифікат дійсний до %s",
		tls.VersionName(state.Version),
		peer.NotAfter.Format("02.01.2006 15:04"),
	)

	reader := bufio.NewReader(tlsConn)
	message, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("[СЕРВЕР] Помилка читання повідомлення від %s: %v", conn.RemoteAddr(), err)
		return
	}

	message = strings.TrimSpace(message)
	if message == "" {
		log.Printf("[СЕРВЕР] Порожнє повідомлення від %s", conn.RemoteAddr())
		return
	}

	log.Printf("[ПОВІДОМЛЕННЯ] Отримано інцидент: %s", message)
	fmt.Fprintln(tlsConn, "[SERVER]: ALERT RECEIVED AND VERIFIED")

	alert := email.Alert{
		Message:    message,
		ReceivedAt: time.Now(),
		ClientCN:   peer.Subject.CommonName,
		Serial:     peer.SerialNumber.String(),
		NotBefore:  peer.NotBefore,
		NotAfter:   peer.NotAfter,
		RemoteAddr: conn.RemoteAddr().String(),
	}

	log.Println("[SMTP] Формування MIME-повідомлення (HTML + вкладення incident_report.log)...")
	log.Printf("[SMTP] Надсилання email на %s через %s...",
		strings.Join(mailConfig.To, ", "),
		mailConfig.Address,
	)

	if err := email.Send(mailConfig, alert); err != nil {
		log.Printf("[SMTP] Помилка доставки: %v", err)
		fmt.Fprintln(tlsConn, "[SERVER]: ALERT RECEIVED, EMAIL DELIVERY FAILED")
		return
	}

	log.Println("[SMTP] Лист про аварію успішно доставлено до поштового шлюзу")
	fmt.Fprintln(tlsConn, "[SERVER]: ALERT PROCESSED AND DISPATCHED")
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
