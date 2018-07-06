// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/lucas-clemente/quic-go (interfaces: OpeningManager)

// Package quic is a generated GoMock package.
package quic

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	handshake "github.com/lucas-clemente/quic-go/internal/handshake"
)

// MockOpeningManager is a mock of OpeningManager interface
type MockOpeningManager struct {
	ctrl     *gomock.Controller
	recorder *MockOpeningManagerMockRecorder
}

// MockOpeningManagerMockRecorder is the mock recorder for MockOpeningManager
type MockOpeningManagerMockRecorder struct {
	mock *MockOpeningManager
}

// NewMockOpeningManager creates a new mock instance
func NewMockOpeningManager(ctrl *gomock.Controller) *MockOpeningManager {
	mock := &MockOpeningManager{ctrl: ctrl}
	mock.recorder = &MockOpeningManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockOpeningManager) EXPECT() *MockOpeningManagerMockRecorder {
	return m.recorder
}

// Get1RTTOpener mocks base method
func (m *MockOpeningManager) Get1RTTOpener() (handshake.Opener, error) {
	ret := m.ctrl.Call(m, "Get1RTTOpener")
	ret0, _ := ret[0].(handshake.Opener)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get1RTTOpener indicates an expected call of Get1RTTOpener
func (mr *MockOpeningManagerMockRecorder) Get1RTTOpener() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get1RTTOpener", reflect.TypeOf((*MockOpeningManager)(nil).Get1RTTOpener))
}

// GetHandshakeOpener mocks base method
func (m *MockOpeningManager) GetHandshakeOpener() handshake.Opener {
	ret := m.ctrl.Call(m, "GetHandshakeOpener")
	ret0, _ := ret[0].(handshake.Opener)
	return ret0
}

// GetHandshakeOpener indicates an expected call of GetHandshakeOpener
func (mr *MockOpeningManagerMockRecorder) GetHandshakeOpener() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetHandshakeOpener", reflect.TypeOf((*MockOpeningManager)(nil).GetHandshakeOpener))
}
