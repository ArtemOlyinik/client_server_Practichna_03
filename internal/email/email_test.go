package email

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"
)

func TestBuildMessageContainsHTMLAndAttachment(t *testing.T) {
	alert := Alert{
		Message:    "CRITICAL_ERROR: Database connection timeout on node-04",
		ReceivedAt: time.Date(2026, 11, 9, 12, 30, 0, 0, time.UTC),
		ClientCN:   "dispatcher-agent-01",
		Serial:     "492048",
		NotBefore:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:   time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		RemoteAddr: "127.0.0.1:58432",
	}

	message, err := BuildMessage("gateway@internal.net", []string{"duty-engineer@internal.net"}, alert)
	if err != nil {
		t.Fatalf("не вдалося зібрати MIME-повідомлення: %v", err)
	}

	parsed, err := mail.ReadMessage(bytes.NewReader(message))
	if err != nil {
		t.Fatalf("не вдалося розібрати заголовки листа: %v", err)
	}

	mediaType, params, err := mime.ParseMediaType(parsed.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("не вдалося розібрати Content-Type: %v", err)
	}
	if mediaType != "multipart/mixed" {
		t.Fatalf("очікували multipart/mixed, отримали %s", mediaType)
	}

	reader := multipart.NewReader(parsed.Body, params["boundary"])
	var htmlBody string
	var attachment string

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("не вдалося прочитати частину MIME: %v", err)
		}

		data, err := io.ReadAll(part)
		if err != nil {
			t.Fatalf("не вдалося прочитати тіло частини: %v", err)
		}

		if part.FileName() == "incident_report.log" {
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
			if err != nil {
				t.Fatalf("вкладення не декодується з Base64: %v", err)
			}
			attachment = string(decoded)
			continue
		}

		if strings.HasPrefix(part.Header.Get("Content-Type"), "text/html") {
			htmlBody = string(data)
		}
	}

	if !strings.Contains(htmlBody, "dispatcher-agent-01") {
		t.Fatal("HTML-тіло не містить CN клієнта")
	}
	if !strings.Contains(htmlBody, "CRITICAL ALERT") {
		t.Fatal("HTML-тіло не містить індикатора тривоги")
	}
	if !strings.Contains(attachment, "INCIDENT REPORT") {
		t.Fatal("вкладення не містить заголовка звіту")
	}
	if !strings.Contains(attachment, "CRITICAL_ERROR: Database connection timeout on node-04") {
		t.Fatal("вкладення не містить тексту інциденту")
	}
}
