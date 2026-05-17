package iru

import (
	"encoding/json"
	"testing"
)

func TestDeviceUnmarshalUserAsObject(t *testing.T) {
	raw := []byte(`{"device_id":"d-1","device_name":"Mac","user":{"id":"u-1","email":"a@x","name":"Alice","active":true}}`)
	var d Device
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if d.DeviceID != "d-1" || d.DeviceName != "Mac" {
		t.Errorf("non-user fields not decoded: %+v", d)
	}
	if d.User.ID != "u-1" || d.User.Email != "a@x" || d.User.Name != "Alice" || !d.User.Active {
		t.Errorf("User not decoded: %+v", d.User)
	}
}

func TestDeviceUnmarshalUserAsEmptyString(t *testing.T) {
	raw := []byte(`{"device_id":"d-2","device_name":"iPhone","user":""}`)
	var d Device
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if d.DeviceID != "d-2" || d.DeviceName != "iPhone" {
		t.Errorf("non-user fields not decoded: %+v", d)
	}
	if (d.User != User{}) {
		t.Errorf("User should be zero, got %+v", d.User)
	}
}

func TestDeviceUnmarshalUserAsNull(t *testing.T) {
	raw := []byte(`{"device_id":"d-3","user":null}`)
	var d Device
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if (d.User != User{}) {
		t.Errorf("User should be zero, got %+v", d.User)
	}
}

func TestDeviceUnmarshalListMixed(t *testing.T) {
	// The actual shape that broke `jellyfish overview`: a list of devices
	// where some have an owner and others don't.
	raw := []byte(`[
		{"device_id":"d-1","user":{"id":"u-1","email":"a@x"}},
		{"device_id":"d-2","user":""},
		{"device_id":"d-3","user":{"id":"u-3","email":"c@x"}}
	]`)
	var devices []Device
	if err := json.Unmarshal(raw, &devices); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(devices) != 3 {
		t.Fatalf("len: got %d, want 3", len(devices))
	}
	if devices[0].User.ID != "u-1" {
		t.Errorf("[0] user: %+v", devices[0].User)
	}
	if (devices[1].User != User{}) {
		t.Errorf("[1] user should be zero, got %+v", devices[1].User)
	}
	if devices[2].User.ID != "u-3" {
		t.Errorf("[2] user: %+v", devices[2].User)
	}
}
