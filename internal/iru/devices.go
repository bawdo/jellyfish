package iru

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ListDevicesPage fetches one page of devices.
func (c *Client) ListDevicesPage(ctx context.Context, f DeviceFilters, limit, offset int) ([]Device, error) {
	q := url.Values{}
	q.Set("limit", strconv.Itoa(limit))
	q.Set("offset", strconv.Itoa(offset))
	if f.UserID != "" {
		q.Set("user_id", f.UserID)
	}
	if f.SerialNumber != "" {
		q.Set("serial_number", f.SerialNumber)
	}
	var out []Device
	if err := c.do(ctx, http.MethodGet, "/devices", q, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListDevices auto-paginates /devices using DefaultLimit.
func (c *Client) ListDevices(ctx context.Context, f DeviceFilters) ([]Device, error) {
	return collect(func(cb func(page []Device) error) error {
		return c.ListDevicesStream(ctx, f, cb)
	})
}

// ListDevicesStream walks every device via Walk[Device]. The callback
// receives one page at a time. Mirrors ListUsersStream / ListDetectionsStream
// so callers can stream + report progress without managing pagination.
func (c *Client) ListDevicesStream(ctx context.Context, f DeviceFilters, cb func(page []Device) error) error {
	return Walk[Device](ctx, DefaultLimit,
		func(ctx context.Context, limit, offset int) ([]Device, error) {
			return c.ListDevicesPage(ctx, f, limit, offset)
		},
		cb,
	)
}

// GetDeviceBySerial returns the device with the given serial number, or
// ErrNotFound. Iru's serial_number filter is a contains match, so every
// filtered result is walked and only a serial equal to the input (ignoring
// case) counts. More than one exact match is an error rather than a guess.
func (c *Client) GetDeviceBySerial(ctx context.Context, serial string) (Device, error) {
	if strings.TrimSpace(serial) == "" {
		return Device{}, fmt.Errorf("invalid serial number %q", serial)
	}
	var matches []Device
	err := c.ListDevicesStream(ctx, DeviceFilters{SerialNumber: serial}, func(page []Device) error {
		for _, d := range page {
			if strings.EqualFold(d.SerialNumber, serial) {
				matches = append(matches, d)
			}
		}
		return nil
	})
	if err != nil {
		return Device{}, err
	}
	switch len(matches) {
	case 0:
		return Device{}, ErrNotFound
	case 1:
		return matches[0], nil
	default:
		return Device{}, fmt.Errorf("serial number %q matches %d devices", serial, len(matches))
	}
}
