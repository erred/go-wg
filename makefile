all:
	df -h
	go test -race -coverprofile=coverage.txt -covermode=atomic
	df -h
	ls /tmp
