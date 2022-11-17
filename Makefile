vet:
	go vet -v ./...

fmt:
	go fmt ./...

test:
	$(TEST_ENV) go test $(TEST_FLAGS) $(shell go list ./...)

testv: TEST_FLAGS += -v
testv: test

testvv: TEST_ENV += TEST_LOGS=1
testvv: testv

testvvv: TEST_ENV += TEST_LOGS=2
testvvv: testv

testvvvv: TEST_ENV += TEST_LOGS=3
testvvvv: testv

.PHONY: vet fmt test testv testvv testvvv testvvvv
