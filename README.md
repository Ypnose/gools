gools
-----

Simple and portable tools written in Go.

The following commands work for all subdirectories.

## Build

	go build -ldflags "-w -s"

## Static build

	CGO_ENABLED=0 go build -ldflags "-w -s"

## Cross-compilation

	go tool dist list
	# For an ARM64 binary running on Linux
	GOOS=linux GOARCH=arm64 go build -ldflags "-w -s"

## License

BSD 3-Clause License. Check
[LICENSE](https://github.com/Ypnose/gools/blob/master/LICENSE).
