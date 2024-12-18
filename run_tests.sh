#!/bin/sh

TEST_DIR="test"

TEST_FILES="abc.txt file50.txt large.txt lorem.txt"

# Check if the sha3 program exists
if [ ! -x "./sha3" ]; then
    echo "Error: './sha3' executable not found or not executable."
    echo "Make sure you have compiled the program before running tests."
    exit 1
fi

ALL_PASSED=true

for f in $TEST_FILES; do
    TEST_FILE="$TEST_DIR/$f"
    if [ ! -f "$TEST_FILE" ]; then
        echo "Warning: Test file '$TEST_FILE' does not exist, skipping."
        continue
    fi

    MY_HASH=$(./sha3 "$TEST_FILE")
    if [ $? -ne 0 ]; then
        echo "Error running './sha3 $TEST_FILE'"
        ALL_PASSED=false
        continue
    fi

    OPENSSL_HASH=$(openssl sha3-256 "$TEST_FILE" | awk '{print $2}')

    # Compare
    if [ "$MY_HASH" = "$OPENSSL_HASH" ]; then
        echo "Test '$f': PASS"
    else
        echo "Test '$f': FAIL"
        ALL_PASSED=false
    fi
    echo "  our hash:     $MY_HASH"
    echo "  openssl hash: $OPENSSL_HASH"
done

if $ALL_PASSED; then
    echo "All tests passed successfully!"
else
    echo "Some tests failed."
    exit 1
fi
