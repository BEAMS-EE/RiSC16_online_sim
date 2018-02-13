from multiprocessing import Pool

import time

def f(x):
	print ">",x
	time.sleep(x)
	print " ",x,">"
	return x*x
    

if __name__ == '__main__':
	pool = Pool(processes=4)              # start 4 worker processes

	#result = pool.apply_async(f, (1,))    # evaluate "f(10)" asynchronously
	#print result.get(timeout=1)           # prints "100" unless your computer is *very* slow
	
	#result = pool.apply_async(f, range(10))
	#print result.get()
	pool.map_async(f, range(10))          # prints "[0, 1, 4,..., 81]"
	print "just after"
	#it = pool.imap(f, range(10))
	#print it.next()                       # prints "0"
	#print it.next()                       # prints "1"
	#print it.next(timeout=1)              # prints "4" unless your computer is *very* slow
	time.sleep(10)
	pool.map_async(f, range(10,20))
	time.sleep(40)
	print "exiting"
	#import time
	#result = pool.apply_async(time.sleep, (10,))
	#print result.get(timeout=1)           # raises TimeoutError