package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"syscall"
	"os/signal"

	"github.com/dchest/captcha"
)

func getTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair("./ssl/server.crt", "./ssl/server.key")
	if err != nil {
		return nil, fmt.Errorf("Failed to load Certificate: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}

func logWithTime(level, message string) {
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("[%s | %s]: %s\n", currentTime, level, message)
}

var blacklist = make(map[string]int64)
var muBlacklist sync.Mutex

const timeout = 100 * 10

func addAddressToBlacklist(address string) {
    muBlacklist.Lock()
    defer muBlacklist.Unlock()
    if blacklist[address] < time.Now().Unix() {
        blacklist[address] = time.Now().Unix() + timeout
    }
}

var requestCount = make(map[string]int)
var mu sync.Mutex

const maxRequests = 50
const rateLimitTimeout = 5 * time.Minute

var (
	captchaVerifiedUsers = make(map[string]bool)
	muCaptcha            sync.Mutex
)

func generateCaptcha() (string, string) {
	id := captcha.New()
	return id, "/captcha/" + id + ".png"
}

func verifyCaptcha(id, userInput string) bool {
	return captcha.VerifyString(id, userInput)
}

func serveCaptcha(w http.ResponseWriter, r *http.Request) {
	captcha.Server(captcha.StdWidth, captcha.StdHeight).ServeHTTP(w, r)
}

func serveCaptchaForm(w http.ResponseWriter, captchaURL, captchaID string) {
    filePath := "./www/captcha.html"
    content, err := os.ReadFile(filePath)
    if err != nil {
        http.Error(w, "Error loading captcha form", http.StatusInternalServerError)
        return
    }

    htmlContent := strings.ReplaceAll(string(content), "{{CAPTCHA_URL}}", captchaURL)
    htmlContent = strings.ReplaceAll(htmlContent, "{{CAPTCHA_ID}}", captchaID)

    w.Header().Set("Content-Type", "text/html")
    w.Write([]byte(htmlContent))
}

func rateLimiter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/growtopia/server_data.php" {
			next.ServeHTTP(w, r)
			return
		}

		ip := r.RemoteAddr
		muBlacklist.Lock()
		blockTime, blocked := blacklist[ip]
		muBlacklist.Unlock()

		if blocked && time.Now().Unix() < blockTime {
			w.WriteHeader(http.StatusForbidden)
			http.ServeFile(w, r, "./www/err/403.html")
			return
		} else if blocked && time.Now().Unix() >= blockTime {
			muBlacklist.Lock()
			delete(blacklist, ip)
			muBlacklist.Unlock()
		}

		mu.Lock()
		count, exists := requestCount[ip]
		if exists && count > maxRequests {
			mu.Unlock()
			addAddressToBlacklist(ip)
			w.WriteHeader(http.StatusTooManyRequests)
			http.ServeFile(w, r, "./www/index.html")
			return
		}

		if !exists {
			requestCount[ip] = 0
		}
		requestCount[ip]++
		mu.Unlock()

		go func(ip string) {
			time.Sleep(rateLimitTimeout)
			mu.Lock()
			defer mu.Unlock()
			requestCount[ip] = 0
		}(ip)

		next.ServeHTTP(w, r)
	})
}

var blockedUserAgents = []string{
	"python-requests",
	"python",
	"Python-urllib",
	"node-fetch",
	"axios",
	"Go-http-client",
	"Mozilla",
	"Chrome",
	"Safari",
	"Firefox",
	"Edge",
	"Opera",
	"Thunder Client",
	"Postman",
	"insomnia",
	"curl",
	"Wget",
	"HttpClient",
	"okhttp",
}

func userAgentBlocker(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent := r.Header.Get("User-Agent")
		for _, blocked := range blockedUserAgents {
			if strings.Contains(strings.ToLower(userAgent), strings.ToLower(blocked)) {
                w.WriteHeader(http.StatusForbidden)
                http.ServeFile(w, r, "./www/err/403.html")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func serverDataHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "DaFaFlare")

	logWithTime("INFO", fmt.Sprintf("Accessed server_data.php from IP: %s", r.RemoteAddr))

	allowedUserAgentPrefix := "UbiServices_SDK"
	if !strings.HasPrefix(r.UserAgent(), allowedUserAgentPrefix) {
		w.WriteHeader(http.StatusForbidden)
		http.ServeFile(w, r, "./www/err/403.html")
		return
	}

	filePath := "./www/growtopia/server_data.php"
	if r.Method == "POST" {
        data, err := os.ReadFile(filePath)
        if err != nil {
            w.WriteHeader(http.StatusInternalServerError)
            http.ServeFile(w, r, "./www/err/500.html")
            return
        }
        w.Header().Set("Content-Type", "text/plain")
        w.Write(data)
    } else {
        w.WriteHeader(http.StatusMethodNotAllowed)
        http.ServeFile(w, r, "./www/err/405.html")
    }
}

func handleCacheRequests(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Server", "DaFaFlare")

    if r.Method != "GET" && r.Method != "POST" {
        w.WriteHeader(http.StatusMethodNotAllowed)
        http.ServeFile(w, r, "./www/err/405.html")
        return
    }

    path := "." + r.URL.Path

	logWithTime("INFO", fmt.Sprintf("Cache Downloading file: %s | from IP %s", r.URL.Path, r.RemoteAddr))

    stat, err := os.Stat(path)
    if err == nil {
        if !stat.IsDir() {
            data, err := ioutil.ReadFile(path)
            if err != nil {
                w.WriteHeader(http.StatusNotFound)
                http.ServeFile(w, r, "./www/err/404.html")
            } else {
                w.Header().Set("Content-Type", "text/plain")
                w.Write(data)
            }
        } else {
            indexPath := path + "/index.html"
            if _, err := os.Stat(indexPath); err == nil {
                http.ServeFile(w, r, indexPath)
                return
            }
        }
    } else if os.IsNotExist(err) {
        logWithTime("INFO", fmt.Sprintf("File not Found, trying Downloading: %s", r.URL.Path))
        url := fmt.Sprintf("https://ubistatic-a.akamaihd.net/0098/0251220240%s", r.URL.Path)

        resp, err := http.Get(url)
        if err != nil || resp.StatusCode != http.StatusOK {
            logWithTime("ERROR", fmt.Sprintf("Failed to Download file: %s, Status: %d", url, resp.StatusCode))
            w.WriteHeader(http.StatusNotFound)
            http.ServeFile(w, r, "./www/err/404.html")
            return
        }
        defer resp.Body.Close()

        data, err := ioutil.ReadAll(resp.Body)
        if err != nil {
            logWithTime("ERROR", fmt.Sprintf("Failed to read content on file on URL: %s", url))
            w.WriteHeader(http.StatusInternalServerError)
            http.ServeFile(w, r, "./www/err/500.html")
            return
        }

        go func() {
            err := os.MkdirAll("./cache"+r.URL.Path[:strings.LastIndex(r.URL.Path, "/")], 0755)
            if err == nil {
                err = ioutil.WriteFile(path, data, 0644)
                if err != nil {
                    logWithTime("ERROR", fmt.Sprintf("Failed to save file cache: %s", path))
                } else {
                    logWithTime("INFO", fmt.Sprintf("File berhasil di-cache: %s", path))
                }
            }
        }()

        w.Header().Set("Content-Type", "text/plain")
        w.Write(data)
    } else {
        w.WriteHeader(http.StatusInternalServerError)
        http.ServeFile(w, r, "./www/err/500.html")
    }
}

func main() {
	tlsConfig, err := getTLSConfig()
	if err != nil {
		log.Fatalf("Gagal memuat sertifikat: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/captcha/", serveCaptcha)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr

		muCaptcha.Lock()
		verified := captchaVerifiedUsers[ip]
		muCaptcha.Unlock()

		if !verified {
			captchaID := r.URL.Query().Get("captcha_id")
			userInput := r.URL.Query().Get("captcha")

			if captchaID != "" && userInput != "" {
				if verifyCaptcha(captchaID, userInput) {
					muCaptcha.Lock()
					captchaVerifiedUsers[ip] = true
					muCaptcha.Unlock()

					http.Redirect(w, r, "/", http.StatusSeeOther)
					return
				}

                w.WriteHeader(http.StatusForbidden)
                http.ServeFile(w, r, "./www/err/400.html")
				return
			}

			captchaID, captchaURL := generateCaptcha()

			w.Header().Set("Content-Type", "text/html")
			serveCaptchaForm(w, captchaURL, captchaID)
			return
		}

		path := "./www" + r.URL.Path

		w.Header().Set("Server", "DaFaFlare")

		if stat, err := os.Stat(path); err == nil {
			if !stat.IsDir() {
				http.ServeFile(w, r, path)
				return
			}
			indexPath := path + "/index.html"
			if _, err := os.Stat(indexPath); err == nil {
				http.ServeFile(w, r, indexPath)
				return
			}
		}

		w.WriteHeader(http.StatusNotFound)
		http.ServeFile(w, r, "./www/err/404.html")
	})

	mux.Handle("/growtopia/server_data.php", userAgentBlocker(http.HandlerFunc(serverDataHandler)))

	mux.HandleFunc("/cache/", handleCacheRequests)

	muxWithLimiter := rateLimiter(mux)

    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGKILL, syscall.SIGTERM)

    go func() {
        for sig := range sigs {
            if sig == syscall.SIGKILL {
                continue
            }
            fmt.Printf("Received signal: %s\n", sig)
        }
    }()

	server := &http.Server{
		Addr:      ":443",
		Handler:   muxWithLimiter,
		TLSConfig: tlsConfig,
	}

	server.ErrorLog = log.New(ioutil.Discard, "", 0)

	fmt.Printf(`
    ╔═════════════════════════════════════════════════════════════════════════════════╗
    ║                                                                                 ║
    ║   ▓█████▄  ▄▄▄        █████▒▄▄▄        █████▒██▓    ▄▄▄       ██▀███  ▓█████    ║
    ║   ▒██▀ ██▌▒████▄    ▓██   ▒▒████▄    ▓██   ▒▓██▒   ▒████▄    ▓██ ▒ ██▒▓█   ▀    ║
    ║   ░██   █▌▒██  ▀█▄  ▒████ ░▒██  ▀█▄  ▒████ ░▒██░   ▒██  ▀█▄  ▓██ ░▄█ ▒▒███      ║
    ║   ░▓█▄   ▌░██▄▄▄▄██ ░▓█▒  ░░██▄▄▄▄██ ░▓█▒  ░▒██░   ░██▄▄▄▄██ ▒██▀▀█▄  ▒▓█  ▄    ║
    ║   ░▒████▓  ▓█   ▓██▒░▒█░    ▓█   ▓██▒░▒█░   ░██████▒▓█   ▓██▒░██▓ ▒██▒░▒████▒   ║
    ║   ▒▒▓  ▒  ▒▒   ▓▒█░ ▒ ░    ▒▒   ▓▒█░ ▒ ░   ░ ▒░▓  ░▒▒   ▓▒█░░ ▒▓ ░▒▓░░░ ▒░ ░    ║
    ║   ░ ▒  ▒   ▒   ▒▒ ░ ░       ▒   ▒▒ ░ ░     ░ ░ ▒  ░ ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ░  ░    ║
    ║   ░ ░  ░   ░   ▒    ░ ░     ░   ▒    ░ ░     ░ ░    ░   ▒     ░░   ░    ░       ║
    ║   ░          ░  ░             ░  ░           ░  ░     ░  ░   ░        ░  ░      ║
    ║   ░                                                                             ║
    ║═════════════════════════════════════════════════════════════════════════════════║
    ║                                                                                 ║
    ║   [INFO] DaFaFlare Active [√] | Synchronized [SSL] [WWW] [CACHE]                ║
    ║   [SYSTEM] Operational & Listening on Port 443                                  ║
    ║                                                                                 ║
    ╚═════════════════════════════════════════════════════════════════════════════════╝
`)
	err = server.ListenAndServeTLS("./ssl/server.crt", "./ssl/server.key")
	if err != nil {
		log.Fatalf("Gagal menjalankan server: %v", err)
	}
}
