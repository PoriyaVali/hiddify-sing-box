package balancer

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"

	"github.com/stretchr/testify/require"
)

func TestTransferFailedRanksBehindEveryNodeThatCarriesData(t *testing.T) {
	t.Parallel()
	verified := getModifiedDelay(&adapter.URLTestHistory{Delay: 900})
	cached := getModifiedDelay(&adapter.URLTestHistory{Delay: 100, IsFromCache: true})
	noUpload := getModifiedDelay(&adapter.URLTestHistory{Delay: 50, TransferFailed: true})
	dead := getModifiedDelay(&adapter.URLTestHistory{Delay: 0})
	require.Less(t, verified, cached)
	require.Less(t, cached, noUpload, "an untested node beats one known not to upload")
	require.Less(t, noUpload, dead, "a node that cannot upload still beats no node at all")

	slower := getModifiedDelay(&adapter.URLTestHistory{Delay: 80, TransferFailed: true})
	require.Less(t, noUpload, slower, "when every node fails the check, the fastest still wins")
}

func TestTransferCandidatesArePickAndFastestLiveNodes(t *testing.T) {
	t.Parallel()
	history := map[string]*adapter.URLTestHistory{
		"a":    {Delay: 300},
		"b":    {Delay: 100},
		"c":    {Delay: 200},
		"d":    {Delay: 50, TransferFailed: true},
		"e":    {Delay: 400},
		"dead": {Delay: monitoring.TimeoutDelay},
	}
	require.Equal(t, []string{"e", "b", "c", "a"}, transferCandidates("e", history, 3))
	require.Equal(t, []string{"b", "c", "a"}, transferCandidates("", history, 3))
	require.NotContains(t, transferCandidates("", history, 10), "dead")
}
