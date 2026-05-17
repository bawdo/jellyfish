package iru

import (
	"bytes"
	"encoding/json"
)

// UnmarshalJSON handles Iru's polymorphic `user` field on the device record.
// Devices with an owner come back as `"user": {...}`; devices without an
// owner (e.g. shared / pool devices, freshly enrolled hardware) come back
// as `"user": ""`. The default decoder rejects the second shape because
// `User` is a struct; this method tolerates empty string and null by
// leaving `Device.User` zero-valued, and otherwise decodes the object as
// usual.
func (d *Device) UnmarshalJSON(data []byte) error {
	type alias Device // strip UnmarshalJSON to avoid recursion
	aux := struct {
		User json.RawMessage `json:"user"`
		*alias
	}{alias: (*alias)(d)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	raw := bytes.TrimSpace(aux.User)
	if len(raw) == 0 || bytes.Equal(raw, []byte(`""`)) || bytes.Equal(raw, []byte("null")) {
		d.User = User{}
		return nil
	}
	return json.Unmarshal(raw, &d.User)
}
