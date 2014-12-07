import sys
import os
from subprocess import call

def main():
	imageFileName    = sys.argv[1]
	passFilePointer  = sys.argv[2]

	passFile = open(passFilePointer, 'r').readlines()
	for word in passFile:
		word = word.strip()
		call(["steghide", "extract", "-sf", imageFileName, "-p", word])

if __name__ == "__main__":
	main()