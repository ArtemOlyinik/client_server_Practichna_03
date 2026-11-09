package email

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"
)

type Config struct {
	Address string
	From    string
	To      []string
}

type Alert struct {
	Message    string
	ReceivedAt time.Time
	ClientCN   string
	Serial     string
	NotBefore  time.Time
	NotAfter   time.Time
	RemoteAddr string
}

// Send формує MIME-лист і передає його SMTP-серверу.
func Send(cfg Config, alert Alert) error {
	if cfg.Address == "" {
		cfg.Address = "127.0.0.1:1025"
	}
	if cfg.From == "" {
		cfg.From = "gateway@internal.net"
	}
	if len(cfg.To) == 0 {
		cfg.To = []string{"duty-engineer@internal.net"}
	}

	message, err := BuildMessage(cfg.From, cfg.To, alert)
	if err != nil {
		return err
	}

	return smtp.SendMail(cfg.Address, nil, cfg.From, cfg.To, message)
}

// BuildMessage збирає multipart/mixed лист: HTML-тіло та вкладений звіт.
func BuildMessage(from string, to []string, alert Alert) ([]byte, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	subject := "Критичний інцидент: " + alert.Message
	headers := []string{
		"From: " + from,
		"To: " + strings.Join(to, ", "),
		"Subject: " + mime.QEncoding.Encode("utf-8", subject),
		"MIME-Version: 1.0",
		fmt.Sprintf("Content-Type: multipart/mixed; boundary=%q", writer.Boundary()),
		"Date: " + alert.ReceivedAt.Format(time.RFC1123Z),
	}
	for _, header := range headers {
		fmt.Fprintf(&body, "%s\r\n", header)
	}
	fmt.Fprint(&body, "\r\n")

	htmlHeader := textproto.MIMEHeader{}
	htmlHeader.Set("Content-Type", "text/html; charset=UTF-8")
	htmlHeader.Set("Content-Transfer-Encoding", "quoted-printable")

	htmlPart, err := writer.CreatePart(htmlHeader)
	if err != nil {
		return nil, err
	}
	htmlWriter := quotedprintable.NewWriter(htmlPart)
	if _, err := htmlWriter.Write([]byte(buildHTML(alert))); err != nil {
		return nil, err
	}
	if err := htmlWriter.Close(); err != nil {
		return nil, err
	}

	attachmentHeader := textproto.MIMEHeader{}
	attachmentHeader.Set("Content-Type", `text/plain; charset=UTF-8; name="incident_report.log"`)
	attachmentHeader.Set("Content-Disposition", `attachment; filename="incident_report.log"`)
	attachmentHeader.Set("Content-Transfer-Encoding", "base64")

	attachmentPart, err := writer.CreatePart(attachmentHeader)
	if err != nil {
		return nil, err
	}
	encoder := base64.NewEncoder(base64.StdEncoding, attachmentPart)
	if _, err := encoder.Write([]byte(buildAttachment(alert))); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

func buildHTML(alert Alert) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="uk">
<body style="margin:0;padding:24px;background:#f4f6f8;font-family:Arial,Helvetica,sans-serif;color:#1f2933;">
  <div style="max-width:680px;margin:0 auto;background:#ffffff;border:1px solid #d9e2ec;border-left:8px solid #c0392b;border-radius:8px;padding:24px;">
    <div style="font-size:12px;letter-spacing:2px;color:#c0392b;font-weight:bold;">CRITICAL ALERT</div>
    <h2 style="margin:8px 0 20px;color:#8e1b10;">Критичний інцидент у диспетчерській мережі</h2>
    <p style="font-size:16px;line-height:1.5;"><strong>Повідомлення:</strong> %s</p>
    <table style="width:100%%;border-collapse:collapse;font-size:14px;">
      <tr><td style="padding:8px 12px;background:#f0f4f8;border:1px solid #d9e2ec;width:42%%;">Час реєстрації</td><td style="padding:8px 12px;border:1px solid #d9e2ec;">%s</td></tr>
      <tr><td style="padding:8px 12px;background:#f0f4f8;border:1px solid #d9e2ec;">Джерело (CN)</td><td style="padding:8px 12px;border:1px solid #d9e2ec;">%s</td></tr>
      <tr><td style="padding:8px 12px;background:#f0f4f8;border:1px solid #d9e2ec;">Серійний номер</td><td style="padding:8px 12px;border:1px solid #d9e2ec;">%s</td></tr>
      <tr><td style="padding:8px 12px;background:#f0f4f8;border:1px solid #d9e2ec;">Віддалена адреса</td><td style="padding:8px 12px;border:1px solid #d9e2ec;">%s</td></tr>
      <tr><td style="padding:8px 12px;background:#f0f4f8;border:1px solid #d9e2ec;">Сертифікат дійсний з</td><td style="padding:8px 12px;border:1px solid #d9e2ec;">%s</td></tr>
      <tr><td style="padding:8px 12px;background:#f0f4f8;border:1px solid #d9e2ec;">Сертифікат дійсний до</td><td style="padding:8px 12px;border:1px solid #d9e2ec;">%s</td></tr>
    </table>
    <p style="margin-top:20px;font-size:13px;color:#52606d;">Лист сформовано автоматично шлюзом Secure Alert Gateway. Вкладення: incident_report.log.</p>
  </div>
</body>
</html>`,
		html.EscapeString(alert.Message),
		alert.ReceivedAt.Format("02.01.2006 15:04:05"),
		html.EscapeString(alert.ClientCN),
		html.EscapeString(alert.Serial),
		html.EscapeString(alert.RemoteAddr),
		alert.NotBefore.Format("02.01.2006 15:04:05"),
		alert.NotAfter.Format("02.01.2006 15:04:05"),
	)
}

func buildAttachment(alert Alert) string {
	return fmt.Sprintf(`INCIDENT REPORT
================
Time: %s
Client CN: %s
Serial: %s
Remote address: %s
Valid from: %s
Valid to: %s
Message: %s
`,
		alert.ReceivedAt.Format(time.RFC3339),
		alert.ClientCN,
		alert.Serial,
		alert.RemoteAddr,
		alert.NotBefore.Format(time.RFC3339),
		alert.NotAfter.Format(time.RFC3339),
		alert.Message,
	)
}
