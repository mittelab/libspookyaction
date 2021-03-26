#!/usr/bin/bash

TIMEOUT=$(( 60 * 10))
LOGFILE=output.log
UPLOAD_RETRIES=3

if [ -z "$ADDR2LINE" ]; then
  ADDR2LINE="$HOME/.platformio/packages/toolchain-xtensa32/bin/xtensa-esp32-elf-addr2line"
fi


while [ $# -gt 0 ]; do
  case "$1" in
  -t|--timeout)
    shift
    TIMEOUT="$1"
    ;;
  -o|--output)
    shift
    LOGFILE="$1"
    ;;
  -r|--retries)
    shift
    UPLOAD_RETRIES="$1"
    ;;
  -h|--help)
    echo "$0 [--timeout $TIMEOUT] [--output $LOGFILE] [-- <pio remote args...>]"
    exit 0
    ;;
  --)
    shift
    break
    ;;
  esac
  shift
done

if ! command -v unbuffer > /dev/null; then
  >&2 echo "Please install unbuffer to correcly passthrough control codes."
  >&2 echo "Use e.g. apt install expect-dev."
  exit 1
fi

while [ "$UPLOAD_RETRIES" -gt 0 ]; do
  (( --UPLOAD_RETRIES ))

  unbuffer pio remote "${@}" 2>&1 \
      | tee >(sed -E 's/\x1B\[(;?[0-9]{1,3})+[mGK]//g' > "$LOGFILE") & TEST_PID=$!

  (sleep "$TIMEOUT" && kill -SIGINT $TEST_PID) & WAITER_PID=$!

  # TODO: This does not seem to pick up the right return code
  wait $TEST_PID
  EXIT_CODE=$?

  kill -SIGTERM $WAITER_PID > /dev/null

  # Did we succeed?
  if [ "$EXIT_CODE" -eq 0 ]; then
    exit 0
  fi

  # Do we have a stack trace?
  if [ -x "$ADDR2LINE" ] && BACKTRACE=$(grep "^Backtrace:" "$LOGFILE"); then
    # Make an attempt at demangling the stack trace. Split the words
    read -r -a BACKTRACE <<< "${BACKTRACE/Backtrace:/}"
    # Find the firmware
    FIRMWARE=$(find .pio/build -mindepth 2 -maxdepth 2 -name \*.elf -and -not -name bootloader.elf | head -n1)
    if [ -n "$FIRMWARE" ] && [ -f "$FIRMWARE" ]; then
      echo "Demangling stack trace ${BACKTRACE[*]}:"
      "$ADDR2LINE" -pfiaC -e "$FIRMWARE" "${BACKTRACE[@]}"
    fi
    exit $EXIT_CODE
  fi

  # Has the job finished before testing?
  if grep -q "^Testing...$" "$LOGFILE" || [ "$EXIT_CODE" -eq 0 ]; then
    exit $EXIT_CODE
  fi
  # Otherwise make a retry
done

exit $EXIT_CODE
