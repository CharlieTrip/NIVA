#!/bin/bash

# Default Values
dserver=2
dthreshold=1
dmu=2



echo "Running experiments..."

# User-Server Changes
for (( f = 1; f <= 2; f = f+1))
do
	for (( n = 100; n <= 500; n = n+50 ))
	do
		for (( m = 2; m <= 10; m=m+1 ))
		do 
			for (( t = 1; t <= m-1; t=t+1 ))
			do 
				for (( mu = t+1 ; mu <= m; mu=mu+1 ))
				do 
					python main.py -c $n -s $m -t $t -m $mu -v 1
					python main.py -c $n -s $m -t $t -m $mu -v $((mu-1))
				done
			done
		done
	done
done