package box_test

import (
	"context"
	"testing"

	box "github.com/sagernet/sing-box"
	tf "github.com/sagernet/sing-box/common/tlsfragment"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// Adaptive Mirage's verdicts go to the log of the box that carries traffic.
// A config check builds a box and closes it without starting it; when that box
// took the verdicts, every subscription refresh during a session silenced
// Mirage in the running box's log.
func TestOnlyARunningBoxReceivesMirageVerdicts(t *testing.T) {
	ctx := include.Context(context.Background())
	options := option.Options{Log: &option.LogOptions{Disabled: true}}
	before := tf.MirageLogSinks()

	checked, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	require.Equal(t, before, tf.MirageLogSinks(), "a box only built, as for a config check, takes no verdicts")
	require.NoError(t, checked.Close())
	require.Equal(t, before, tf.MirageLogSinks())

	running, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	require.NoError(t, running.Start())
	require.Equal(t, before+1, tf.MirageLogSinks(), "a started box receives them")

	// A config check while it runs leaves it its verdicts.
	check, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	require.NoError(t, check.Close())
	require.Equal(t, before+1, tf.MirageLogSinks())

	require.NoError(t, running.Close())
	require.Equal(t, before, tf.MirageLogSinks(), "closing it takes its log away")
}

// The outbound monitor's scheduler read its ticker from the monitor after it
// had started; a box closed at once (a quick disconnect, a network analysis
// trial) had already cleared it, and the scheduler's select took .C of a nil
// ticker. The race detector shows it on the old code every time.
func TestABoxClosedRightAfterItStartsShutsDownCleanly(t *testing.T) {
	ctx := include.Context(context.Background())
	options := option.Options{Log: &option.LogOptions{Disabled: true}}
	for range 20 {
		instance, err := box.New(box.Options{Context: ctx, Options: options})
		require.NoError(t, err)
		require.NoError(t, instance.Start())
		require.NoError(t, instance.Close())
	}
}
