package cmd

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/bawdo/jellyfish/internal/email"
	"github.com/bawdo/jellyfish/internal/iru"
)

// overviewFakeClient is a fakeClient subset that lets each user own a
// distinct device set. The base fakeClient's single devices slice can't
// express "alice has d1, bob has d2".
type overviewFakeClient struct {
	*fakeClient
	devicesByUser map[string][]iru.Device // key = user.ID
}

func (f *overviewFakeClient) ListDevices(_ context.Context, filt iru.DeviceFilters) ([]iru.Device, error) {
	return f.devicesByUser[filt.UserID], nil
}

func TestAssembleOverviewSumsAndSorts(t *testing.T) {
	base := &fakeClient{
		users: []iru.User{
			{ID: "u-alice", Name: "Alice", Email: "alice@x"},
			{ID: "u-bob", Name: "Bob", Email: "bob@x"},
			{ID: "u-carol", Name: "Carol", Email: "carol@x"}, // no devices -> excluded
		},
		detections: []iru.Detection{
			{DeviceID: "d-a1", CVEID: "CVE-1", CVSSScore: 9.8, Severity: "Critical"},
			{DeviceID: "d-a1", CVEID: "CVE-2", CVSSScore: 7.5, Severity: "High"},
			{DeviceID: "d-a2", CVEID: "CVE-3", CVSSScore: 5.0, Severity: "Medium"},
			{DeviceID: "d-b1", CVEID: "CVE-4", CVSSScore: 2.5, Severity: "Low"},
			{DeviceID: "d-other", CVEID: "CVE-X", CVSSScore: 9.0, Severity: "Critical"}, // belongs to no listed device
		},
	}
	c := &overviewFakeClient{
		fakeClient: base,
		devicesByUser: map[string][]iru.Device{
			"u-alice": {{DeviceID: "d-a1"}, {DeviceID: "d-a2"}},
			"u-bob":   {{DeviceID: "d-b1"}},
			"u-carol": nil,
		},
	}

	view, err := assembleOverview(context.Background(), c, &bytes.Buffer{}, false)
	if err != nil {
		t.Fatalf("assembleOverview: %v", err)
	}

	// Carol has no devices -> excluded.
	if len(view.Users) != 2 {
		t.Fatalf("Users len: got %d, want 2 (carol excluded)", len(view.Users))
	}

	// Alice: 9.8 + 7.5 + 5.0 = 22.3, 3 issues, C=1 H=1 M=1 L=0, 2 devices.
	// Bob:   2.5,                    1 issue,  C=0 H=0 M=0 L=1, 1 device.
	// Sort: SecScore desc -> Alice rank 1, Bob rank 2.
	want := []email.UserStats{
		{UserID: "u-alice", Name: "Alice", Email: "alice@x", DeviceCount: 2,
			SecScore: 22.3, TotalIssues: 3, Critical: 1, High: 1, Medium: 1, Low: 0, Rank: 1},
		{UserID: "u-bob", Name: "Bob", Email: "bob@x", DeviceCount: 1,
			SecScore: 2.5, TotalIssues: 1, Critical: 0, High: 0, Medium: 0, Low: 1, Rank: 2},
	}
	for i := range want {
		// float compare with one-decimal tolerance to dodge FP noise.
		if diff := view.Users[i].SecScore - want[i].SecScore; diff > 0.05 || diff < -0.05 {
			t.Errorf("user[%d] SecScore: got %v want %v", i, view.Users[i].SecScore, want[i].SecScore)
		}
		// zero the float for the rest of the comparison so DeepEqual matches.
		view.Users[i].SecScore = want[i].SecScore
	}
	if !reflect.DeepEqual(view.Users, want) {
		t.Errorf("Users mismatch:\n got: %#v\nwant: %#v", view.Users, want)
	}

	if view.Totals.UserCount != 2 || view.Totals.DeviceCount != 3 || view.Totals.TotalIssues != 4 {
		t.Errorf("Totals counts wrong: %+v", view.Totals)
	}
	if view.Totals.Critical != 1 || view.Totals.High != 1 || view.Totals.Medium != 1 || view.Totals.Low != 1 {
		t.Errorf("Totals severity wrong: %+v", view.Totals)
	}
	// (22.3 + 2.5) / 2 = 12.4
	if diff := view.Averages.SecScorePerUser - 12.4; diff > 0.05 || diff < -0.05 {
		t.Errorf("Averages.SecScorePerUser: got %v want 12.4", view.Averages.SecScorePerUser)
	}

	if len(view.MostDangerousFive) != 2 || view.MostDangerousFive[0].UserID != "u-alice" {
		t.Errorf("MostDangerousFive wrong: %+v", view.MostDangerousFive)
	}
	if len(view.BestFive) != 2 || view.BestFive[0].UserID != "u-bob" {
		t.Errorf("BestFive wrong: %+v", view.BestFive)
	}
}

func TestAssembleOverviewEmptyRosterErrors(t *testing.T) {
	c := &overviewFakeClient{
		fakeClient:    &fakeClient{users: []iru.User{{ID: "u1", Name: "x"}}},
		devicesByUser: map[string][]iru.Device{"u1": nil},
	}
	_, err := assembleOverview(context.Background(), c, &bytes.Buffer{}, false)
	if err == nil || err.Error() == "" {
		t.Fatalf("expected an empty-roster error, got nil")
	}
}

func TestAssembleOverviewTieBreakerByName(t *testing.T) {
	c := &overviewFakeClient{
		fakeClient: &fakeClient{
			users: []iru.User{
				{ID: "u-b", Name: "Beta", Email: "b@x"},
				{ID: "u-a", Name: "Alpha", Email: "a@x"},
			},
			// both score 0 (no detections), so name asc decides
			detections: nil,
		},
		devicesByUser: map[string][]iru.Device{
			"u-a": {{DeviceID: "d-a"}},
			"u-b": {{DeviceID: "d-b"}},
		},
	}
	view, err := assembleOverview(context.Background(), c, &bytes.Buffer{}, false)
	if err != nil {
		t.Fatalf("assembleOverview: %v", err)
	}
	if view.Users[0].Name != "Alpha" || view.Users[1].Name != "Beta" {
		t.Fatalf("name-asc tiebreaker broken: %+v", view.Users)
	}
}

func TestSecScoreTier(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{0.0, "good"},
		{4.9, "good"},
		{5.0, "medium"},
		{29.9, "medium"},
		{30.0, "high"},
		{99.9, "high"},
		{100.0, "critical"},
		{500.0, "critical"},
	}
	for _, c := range cases {
		if got := secScoreTier(c.score); got != c.want {
			t.Errorf("secScoreTier(%v) = %q, want %q", c.score, got, c.want)
		}
	}
}
