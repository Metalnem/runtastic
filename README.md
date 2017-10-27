# Runtastic Archiver [![Build Status](https://travis-ci.org/Metalnem/runtastic.svg?branch=master)](https://travis-ci.org/Metalnem/runtastic) [![GoDoc](https://godoc.org/github.com/metalnem/runtastic?status.svg)](http://godoc.org/github.com/metalnem/runtastic) [![Go Report Card](https://goreportcard.com/badge/github.com/metalnem/runtastic)](https://goreportcard.com/report/github.com/metalnem/runtastic) [![license](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://raw.githubusercontent.com/metalnem/runtastic/master/LICENSE)
Command line tool to archive all your Runtastic activities.

## Downloads

[Windows](https://github.com/Metalnem/runtastic/releases/download/v2.1.1/runtastic-win64-2.1.1.zip)  
[Mac OS X](https://github.com/Metalnem/runtastic/releases/download/v2.1.1/runtastic-darwin64-2.1.1.zip)  
[Linux](https://github.com/Metalnem/runtastic/releases/download/v2.1.1/runtastic-linux64-2.1.1.zip)

## Usage

```
$ ./runtastic
Usage of ./runtastic:
  -email string
    	Email (required)
  -password string
    	Password (required)
  -format string
    	Output format (gpx or tcx)
```

If your are not very comfortable with the command line, you can watch this
[video tutorial](https://www.youtube.com/watch?v=EMYozDasOv8) (courtesy
of [Michael Pohl](https://github.com/mipapo), creator of [RUNALYZE](https://runalyze.com/en/login)).

## Example

```
$ ./runtastic -email user@example.org -password secret123 -format tcx
```
