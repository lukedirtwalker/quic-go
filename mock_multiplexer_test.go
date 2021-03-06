// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/lukedirtwalker/quic-go (interfaces: Multiplexer)

// Package quic is a generated GoMock package.
package quic

import (
	net "net"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	protocol "github.com/lukedirtwalker/quic-go/internal/protocol"
)

// MockMultiplexer is a mock of Multiplexer interface
type MockMultiplexer struct {
	ctrl     *gomock.Controller
	recorder *MockMultiplexerMockRecorder
}

// MockMultiplexerMockRecorder is the mock recorder for MockMultiplexer
type MockMultiplexerMockRecorder struct {
	mock *MockMultiplexer
}

// NewMockMultiplexer creates a new mock instance
func NewMockMultiplexer(ctrl *gomock.Controller) *MockMultiplexer {
	mock := &MockMultiplexer{ctrl: ctrl}
	mock.recorder = &MockMultiplexerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockMultiplexer) EXPECT() *MockMultiplexerMockRecorder {
	return m.recorder
}

// AddConn mocks base method
func (m *MockMultiplexer) AddConn(arg0 net.PacketConn, arg1 int) (packetHandlerManager, error) {
	ret := m.ctrl.Call(m, "AddConn", arg0, arg1)
	ret0, _ := ret[0].(packetHandlerManager)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddConn indicates an expected call of AddConn
func (mr *MockMultiplexerMockRecorder) AddConn(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddConn", reflect.TypeOf((*MockMultiplexer)(nil).AddConn), arg0, arg1)
}

// AddHandler mocks base method
func (m *MockMultiplexer) AddHandler(arg0 net.PacketConn, arg1 protocol.ConnectionID, arg2 packetHandler) error {
	ret := m.ctrl.Call(m, "AddHandler", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddHandler indicates an expected call of AddHandler
func (mr *MockMultiplexerMockRecorder) AddHandler(arg0, arg1, arg2 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddHandler", reflect.TypeOf((*MockMultiplexer)(nil).AddHandler), arg0, arg1, arg2)
}
