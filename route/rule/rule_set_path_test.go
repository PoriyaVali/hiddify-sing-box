package rule

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing/service/filemanager"
	"github.com/stretchr/testify/require"
)

// The desktop build could not start at all with a bundled rule-set.
//
// `filemanager.BasePath` answers "is this already absolute?" with
// `strings.HasPrefix(name, "/")`. Every Windows absolute path fails that test,
// so it was joined to the working directory and the core tried to open
// `C:\...\hiddify\C:\...\rulesets\singbox\geoip-ir.srs`, which is not a legal
// filename. Android was unaffected because its paths do start with `/`.
//
// The relative case is asserted alongside it so the fix cannot be "stop
// calling BasePath", which would break every path the core resolves itself.
func TestLocalRuleSetPathKeepsAbsolutePathsIntact(t *testing.T) {
	base := filepath.Join(string(filepath.Separator)+"srv", "core")
	ctx := filemanager.WithDefault(context.Background(), base, "", 0, 0)

	absolute := filepath.Join(t.TempDir(), "geoip-ir.srs")
	require.Equal(t, absolute, localRuleSetPath(ctx, absolute),
		"an absolute path must be used as given, never appended to the working directory")

	// The trap itself, asserted rather than described - otherwise this test
	// would pass just as happily against the broken version. If it ever fails,
	// upstream has fixed BasePath and localRuleSetPath can be deleted.
	if filepath.Separator == '\\' {
		require.NotEqual(t, absolute, filemanager.BasePath(ctx, absolute),
			"BasePath is expected to mangle a Windows absolute path; that is why this helper exists")
	}

	relative := filepath.Join("rulesets", "singbox", "geoip-ir.srs")
	require.Equal(t, filepath.Join(base, relative), localRuleSetPath(ctx, relative),
		"a relative path still resolves against the base")

	// With no file manager in the context there is no base to join to, so both
	// forms have to come back unchanged.
	bare := context.Background()
	require.Equal(t, absolute, localRuleSetPath(bare, absolute))
	require.Equal(t, relative, localRuleSetPath(bare, relative))
}
