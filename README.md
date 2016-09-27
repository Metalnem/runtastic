# Runtastic archiver [![Build Status](https://travis-ci.org/Metalnem/runtastic-cli.svg?branch=master)](https://travis-ci.org/Metalnem/runtastic-cli) [![Go Report Card](https://goreportcard.com/badge/github.com/metalnem/runtastic-cli)](https://goreportcard.com/report/github.com/metalnem/runtastic-cli) [![license](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://raw.githubusercontent.com/metalnem/runtastic-cli/master/LICENSE)
Command line tool to archive all your Runtastic activities.

## Download

[Windows](https://github.com/Metalnem/runtastic-cli/releases/download/v1.1.0/runtastic-cli-win64-1.1.0.zip)
[Mac OS X](https://github.com/Metalnem/runtastic-cli/releases/download/v1.1.0/runtastic-cli-darwin64-1.1.0.zip)

## Usage

```
$ ./runtastic-cli
Usage of ./runtastic-cli:
  -email string
    	Email (required)
  -format string
    	Optional export format (gpx, tcx or kml) (default "gpx")
  -password string
    	Password (required)
```

## Example

```
$ ./runtastic-cli -email user@example.org -password secret123 -format gpx
```
