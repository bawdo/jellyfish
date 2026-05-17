package email

import "time"

// UserStats is a single user's contribution to the overview. SecScore is the
// sum of CVSSScore across every detection on every device this user owns.
// The four severity counts mirror Iru's "Critical | High | Medium | Low"
// labels; detections with "Undefined" or empty severity are still counted
// in TotalIssues and SecScore but do not increment any severity bucket.
type UserStats struct {
	UserID      string  `json:"user_id" yaml:"user_id"`
	Name        string  `json:"name" yaml:"name"`
	Email       string  `json:"email" yaml:"email"`
	DeviceCount int     `json:"device_count" yaml:"device_count"`
	SecScore    float64 `json:"sec_score" yaml:"sec_score"`
	TotalIssues int     `json:"total_issues" yaml:"total_issues"`
	Critical    int     `json:"critical_issues" yaml:"critical_issues"`
	High        int     `json:"high_issues" yaml:"high_issues"`
	Medium      int     `json:"medium_issues" yaml:"medium_issues"`
	Low         int     `json:"low_issues" yaml:"low_issues"`
	Rank        int     `json:"rank" yaml:"rank"` // 1 = highest SecScore in the org
}

// OverviewTotals are sums across users with at least one device.
type OverviewTotals struct {
	UserCount   int     `json:"user_count" yaml:"user_count"`
	DeviceCount int     `json:"device_count" yaml:"device_count"`
	TotalIssues int     `json:"total_issues" yaml:"total_issues"`
	Critical    int     `json:"critical_issues" yaml:"critical_issues"`
	High        int     `json:"high_issues" yaml:"high_issues"`
	Medium      int     `json:"medium_issues" yaml:"medium_issues"`
	Low         int     `json:"low_issues" yaml:"low_issues"`
	SecScore    float64 `json:"sec_score" yaml:"sec_score"`
}

// OverviewAverages are the per-user values, denominator = UserCount.
type OverviewAverages struct {
	DevicesPerUser  float64 `json:"devices_per_user" yaml:"devices_per_user"`
	IssuesPerUser   float64 `json:"issues_per_user" yaml:"issues_per_user"`
	SecScorePerUser float64 `json:"sec_score_per_user" yaml:"sec_score_per_user"`
	CriticalPerUser float64 `json:"critical_per_user" yaml:"critical_per_user"`
	HighPerUser     float64 `json:"high_per_user" yaml:"high_per_user"`
	MediumPerUser   float64 `json:"medium_per_user" yaml:"medium_per_user"`
	LowPerUser      float64 `json:"low_per_user" yaml:"low_per_user"`
}

// OverviewView is the full payload that every renderer (table/json/yaml/csv/
// email) consumes. Users is the full roster sorted by SecScore desc, name
// asc. BestFive holds the five entries with the lowest SecScore (sorted
// asc); MostDangerousFive holds the top five (sorted desc). Me is set only
// when rendering a per-user email copy and points at the recipient's entry
// in Users (same pointer-equality, not a clone).
type OverviewView struct {
	Tenant            string           `json:"tenant" yaml:"tenant"`
	GeneratedAt       time.Time        `json:"generated_at" yaml:"generated_at"`
	Totals            OverviewTotals   `json:"totals" yaml:"totals"`
	Averages          OverviewAverages `json:"averages" yaml:"averages"`
	BestFive          []UserStats      `json:"best_five" yaml:"best_five"`
	MostDangerousFive []UserStats      `json:"most_dangerous_five" yaml:"most_dangerous_five"`
	Users             []UserStats      `json:"users" yaml:"users"`
	Me                *UserStats       `json:"me,omitempty" yaml:"me,omitempty"`
}

// OverviewInput is the typed shape NewOverviewRenderer.Render expects via
// the output.Renderer Render(w, v any) call site.
type OverviewInput struct {
	View OverviewView
}

// SecScore tier thresholds. Renderers use these to pick border / rank-tile
// colours so the table, email, and docs agree on what a "high" user looks
// like. Documented in the README and the spec. May be retuned after
// real-data review.
const (
	SecScoreCriticalAt = 100.0
	SecScoreHighAt     = 30.0
	SecScoreMediumAt   = 5.0
)
