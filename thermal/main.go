package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	thermalPath = "/sys/class/thermal"
)

type ThermalSensor struct {
	Name  string
	Type  string
	Value float64
	Path  string
}

func main() {
	// Prevent running as root
	if os.Geteuid() == 0 {
		fmt.Fprintf(os.Stderr, "This program must not be run as root for security reasons\n")
		os.Exit(2)
	}

	sensors, warnings, err := findThermalSensors()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding thermal sensors: %v\n", err)
		os.Exit(1)
	}

	if len(sensors) == 0 {
		fmt.Println("No thermal sensors found")
		return
	}

	fmt.Println("Thermal sensors found:")
	fmt.Println("======================")
	for i, sensor := range sensors {
		fmt.Printf("%2d. Name: %s\n", i+1, sensor.Name)
		fmt.Printf("    Type: %s\n", sensor.Type)
		fmt.Printf("    Temperature: %.2f°C\n", sensor.Value/1000.0) // Convert from millidegrees to degrees
		fmt.Printf("    Path: %s\n", sensor.Path)
		if i < len(sensors)-1 {
			fmt.Println()
		}
	}
	
	// Print all collected warnings at the end
	if len(warnings) > 0 {
		fmt.Fprintf(os.Stderr, "Warnings:\n")
		for i, warning := range warnings {
			if i < len(warnings)-1 {
				fmt.Fprintf(os.Stderr, "- %s\n", warning)
			} else {
				fmt.Fprintf(os.Stderr, "- %s", warning)
			}
		}
	}
}

func findThermalSensors() ([]ThermalSensor, []string, error) {
	var sensors []ThermalSensor
	var warnings []string

	// Check if thermal path exists
	if _, err := os.Stat(thermalPath); os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("thermal subsystem path %s does not exist", thermalPath)
	}

	// Find all thermal zone directories
	thermalZones, err := filepath.Glob(filepath.Join(thermalPath, "thermal_zone*"))
	if err != nil {
		return nil, nil, err
	}

	for _, zonePath := range thermalZones {
		sensor, err := readThermalZone(zonePath)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Could not read thermal zone %s: %v", zonePath, err))
			continue
		}
		sensors = append(sensors, sensor)
	}

	// Additionally check for hwmon devices which might contain thermal sensors
	hwmonDevices, err := filepath.Glob("/sys/class/hwmon/hwmon*")
	if err == nil {
		for _, hwmonPath := range hwmonDevices {
			hwmonSensors, hwmonWarnings, err := readHwmonSensors(hwmonPath)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("Could not read hwmon device %s: %v", hwmonPath, err))
				continue
			}
			warnings = append(warnings, hwmonWarnings...)
			sensors = append(sensors, hwmonSensors...)
		}
	}

	return sensors, warnings, nil
}

func readThermalZone(zonePath string) (ThermalSensor, error) {
	sensor := ThermalSensor{
		Path: zonePath,
		Name: filepath.Base(zonePath),
	}

	// Read sensor type - limit read size to prevent memory exhaustion
	typeBytes, err := os.ReadFile(filepath.Join(zonePath, "type"))
	if err != nil {
		return sensor, err
	}
	if len(typeBytes) > 1024 {
		typeBytes = typeBytes[:1024]
	}
	sensor.Type = strings.TrimSpace(string(typeBytes))

	// Read temperature - limit read size to prevent memory exhaustion
	tempBytes, err := os.ReadFile(filepath.Join(zonePath, "temp"))
	if err != nil {
		return sensor, err
	}
	if len(tempBytes) > 1024 {
		tempBytes = tempBytes[:1024]
	}
	tempStr := strings.TrimSpace(string(tempBytes))
	temp, err := strconv.ParseFloat(tempStr, 64)
	if err != nil {
		return sensor, fmt.Errorf("invalid temperature value: %s", tempStr)
	}
	sensor.Value = temp

	return sensor, nil
}

func readHwmonSensors(hwmonPath string) ([]ThermalSensor, []string, error) {
	var sensors []ThermalSensor
	var warnings []string

	// Try to get device name
	nameBytes, err := os.ReadFile(filepath.Join(hwmonPath, "name"))
	deviceName := "unknown"
	if err == nil {
		if len(nameBytes) > 1024 {
			nameBytes = nameBytes[:1024]
		}
		deviceName = strings.TrimSpace(string(nameBytes))
	}

	// Look for temp*_input files which contain temperature readings
	tempFiles, err := filepath.Glob(filepath.Join(hwmonPath, "temp*_input"))
	if err != nil {
		return nil, warnings, err
	}

	// Cap the number of files to prevent resource exhaustion
	maxFiles := 100
	if len(tempFiles) > maxFiles {
		tempFiles = tempFiles[:maxFiles]
		warnings = append(warnings, fmt.Sprintf("Limited hwmon sensor files to %d for %s", maxFiles, hwmonPath))
	}

	for _, tempFile := range tempFiles {
		baseName := filepath.Base(tempFile)
		sensorID := strings.TrimSuffix(baseName, "_input")

		// Read temperature value
		tempBytes, err := os.ReadFile(tempFile)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Could not read temperature from %s: %v", tempFile, err))
			continue
		}
		if len(tempBytes) > 1024 {
			tempBytes = tempBytes[:1024]
		}
		tempStr := strings.TrimSpace(string(tempBytes))
		temp, err := strconv.ParseFloat(tempStr, 64)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Invalid temperature value in %s: %s", tempFile, tempStr))
			continue
		}

		// Try to read sensor label
		labelFile := filepath.Join(hwmonPath, sensorID+"_label")
		sensorName := sensorID
		labelBytes, err := os.ReadFile(labelFile)
		if err == nil {
			if len(labelBytes) > 1024 {
				labelBytes = labelBytes[:1024]
			}
			sensorName = strings.TrimSpace(string(labelBytes))
		}

		sensor := ThermalSensor{
			Name:  fmt.Sprintf("%s (%s)", deviceName, sensorName),
			Type:  "hwmon",
			Value: temp,
			Path:  tempFile,
		}
		sensors = append(sensors, sensor)
	}

	return sensors, warnings, nil
}
