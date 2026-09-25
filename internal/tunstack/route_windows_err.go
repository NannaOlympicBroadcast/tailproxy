//go:build windows

package tunstack

import "golang.org/x/sys/windows"

// windowsErrObjectExists is returned when a route is already present.
var windowsErrObjectExists error = windows.ERROR_OBJECT_ALREADY_EXISTS
