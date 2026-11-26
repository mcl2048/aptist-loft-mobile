package testsupport

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
)

// Close checks fixture teardown while accepting a prior owner close/cancel.
// Production resource release is asserted at the consuming runtime boundary.
func Close(t *testing.T, closer io.Closer) {
	t.Helper()
	if err := closer.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
		t.Errorf("fixture cleanup failed: %v", err)
	}
}
