nfqnl_test: main.o
	g++ -g -o nfqnl_test main.cpp -lnetfilter_queue

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f nfqnl_test
	rm -f *.0

