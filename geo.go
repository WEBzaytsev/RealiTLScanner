package main

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

const geoDBURL = "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-Country.mmdb"
const geoDBPath = "Country.mmdb"
const geoDBTempPath = "Country.mmdb.tmp"

type Geo struct {
	geoReader *geoip2.Reader
	mu        sync.Mutex
}

// needsUpdate проверяет нужно ли обновление базы данных
func needsUpdate(localPath string) (bool, error) {
	// Проверить существование локального файла
	localInfo, err := os.Stat(localPath)
	if os.IsNotExist(err) {
		return true, nil // файла нет - нужна загрузка
	}
	if err != nil {
		return false, err
	}

	// HEAD запрос к GitHub для получения размера
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Head(geoDBURL)
	if err != nil {
		slog.Debug("Failed to check GeoIP database updates", "err", err)
		return false, nil // если не можем проверить - используем старую базу
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	remoteSize := resp.ContentLength
	if remoteSize <= 0 {
		return false, nil
	}

	// Сравнить размеры
	if localInfo.Size() != remoteSize {
		slog.Info("GeoIP database update available", "local_size", localInfo.Size(), "remote_size", remoteSize)
		return true, nil
	}

	return false, nil
}

// downloadCountryDB скачивает базу данных Country.mmdb
func downloadCountryDB() error {
	slog.Info("Downloading GeoIP database...", "url", geoDBURL)

	client := &http.Client{
		Timeout: 60 * time.Second,
	}
	resp, err := client.Get(geoDBURL)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	// Создать временный файл
	tmpFile, err := os.Create(geoDBTempPath)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmpFile.Close()

	// Копировать содержимое с отображением прогресса
	totalSize := resp.ContentLength
	var downloaded int64
	buffer := make([]byte, 32*1024)

	for {
		n, err := resp.Body.Read(buffer)
		if n > 0 {
			_, writeErr := tmpFile.Write(buffer[:n])
			if writeErr != nil {
				os.Remove(geoDBTempPath)
				return fmt.Errorf("failed to write: %w", writeErr)
			}
			downloaded += int64(n)
			
			if totalSize > 0 {
				progress := float64(downloaded) / float64(totalSize) * 100
				if downloaded%(1024*1024) == 0 || err == io.EOF {
					slog.Debug("Download progress", "downloaded_mb", downloaded/(1024*1024), "total_mb", totalSize/(1024*1024), "percent", fmt.Sprintf("%.1f%%", progress))
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			os.Remove(geoDBTempPath)
			return fmt.Errorf("failed to read: %w", err)
		}
	}

	tmpFile.Close()

	// Атомарно переименовать временный файл
	if err := os.Rename(geoDBTempPath, geoDBPath); err != nil {
		os.Remove(geoDBTempPath)
		return fmt.Errorf("failed to rename: %w", err)
	}

	slog.Info("GeoIP database downloaded successfully", "size_mb", downloaded/(1024*1024))
	return nil
}

func NewGeo() *Geo {
	geo := &Geo{
		mu: sync.Mutex{},
	}

	// Проверить нужно ли обновление
	needUpdate, err := needsUpdate(geoDBPath)
	if err != nil {
		slog.Warn("Failed to check GeoIP database updates", "err", err)
	}

	if needUpdate {
		if err := downloadCountryDB(); err != nil {
			slog.Warn("Failed to download GeoIP database", "err", err)
		}
	}

	// Открыть базу данных
	reader, err := geoip2.Open(geoDBPath)
	if err != nil {
		slog.Warn("Cannot open Country.mmdb", "err", err)
		return geo
	}
	slog.Info("Enabled GeoIP")
	geo.geoReader = reader
	return geo
}

func (o *Geo) GetGeo(ip net.IP) string {
	if o.geoReader == nil {
		return "N/A"
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	country, err := o.geoReader.Country(ip)
	if err != nil {
		slog.Debug("Error reading geo", "err", err)
		return "N/A"
	}
	return country.Country.IsoCode
}
