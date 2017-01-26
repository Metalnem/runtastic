package export

import (
	"fmt"
	"io"
	"time"
)

func getFilename(t time.Time, ext string) string {
	s := t.Local().Format("2006-01-02 15.04.05")
	return fmt.Sprintf("Runtastic %s.%s", s, ext)
}

func checkedClose(c io.Closer, err *error) {
	if cerr := c.Close(); cerr != nil && *err == nil {
		*err = cerr
	}
}
