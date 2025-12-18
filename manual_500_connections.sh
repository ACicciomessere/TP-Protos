rm -f file.txt

for i in {1..500}; do
  (
    curl -s -o /dev/null \
      -w "req=%03d status=%{http_code} exit=$?\n" \
      -x socks5://user:password@localhost:1080 \
      http://localhost:8888/
  ) >> file.txt &
done
wait

grep -c 'status=200 exit=0' file.txt