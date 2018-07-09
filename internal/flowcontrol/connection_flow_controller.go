package flowcontrol

import (
	"fmt"

	"github.com/lukedirtwalker/quic-go/internal/congestion"
	"github.com/lukedirtwalker/quic-go/internal/protocol"
	"github.com/lukedirtwalker/quic-go/internal/utils"
	"github.com/lukedirtwalker/quic-go/qerr"
)

type connectionFlowController struct {
	lastBlockedAt protocol.ByteCount
	baseFlowController

	queueWindowUpdate func()
}

var _ ConnectionFlowController = &connectionFlowController{}

// NewConnectionFlowController gets a new flow controller for the connection
// It is created before we receive the peer's transport paramenters, thus it starts with a sendWindow of 0.
func NewConnectionFlowController(
	receiveWindow protocol.ByteCount,
	maxReceiveWindow protocol.ByteCount,
	queueWindowUpdate func(),
	rttStats *congestion.RTTStats,
	logger utils.Logger,
) ConnectionFlowController {
	return &connectionFlowController{
		baseFlowController: baseFlowController{
			rttStats:             rttStats,
			receiveWindow:        receiveWindow,
			receiveWindowSize:    receiveWindow,
			maxReceiveWindowSize: maxReceiveWindow,
			logger:               logger,
		},
		queueWindowUpdate: queueWindowUpdate,
	}
}

func (c *connectionFlowController) SendWindowSize() protocol.ByteCount {
	return c.baseFlowController.sendWindowSize()
}

// IsNewlyBlocked says if it is newly blocked by flow control.
// For every offset, it only returns true once.
// If it is blocked, the offset is returned.
func (c *connectionFlowController) IsNewlyBlocked() (bool, protocol.ByteCount) {
	if c.sendWindowSize() != 0 || c.sendWindow == c.lastBlockedAt {
		return false, 0
	}
	c.lastBlockedAt = c.sendWindow
	return true, c.sendWindow
}

// IncrementHighestReceived adds an increment to the highestReceived value
func (c *connectionFlowController) IncrementHighestReceived(increment protocol.ByteCount) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.highestReceived += increment
	if c.checkFlowControlViolation() {
		return qerr.Error(qerr.FlowControlReceivedTooMuchData, fmt.Sprintf("Received %d bytes for the connection, allowed %d bytes", c.highestReceived, c.receiveWindow))
	}
	return nil
}

func (c *connectionFlowController) MaybeQueueWindowUpdate() {
	c.mutex.Lock()
	hasWindowUpdate := c.hasWindowUpdate()
	c.mutex.Unlock()
	if hasWindowUpdate {
		c.queueWindowUpdate()
	}
}

func (c *connectionFlowController) GetWindowUpdate() protocol.ByteCount {
	c.mutex.Lock()
	oldWindowSize := c.receiveWindowSize
	offset := c.baseFlowController.getWindowUpdate()
	if oldWindowSize < c.receiveWindowSize {
		c.logger.Debugf("Increasing receive flow control window for the connection to %d kB", c.receiveWindowSize/(1<<10))
	}
	c.mutex.Unlock()
	return offset
}

// EnsureMinimumWindowSize sets a minimum window size
// it should make sure that the connection-level window is increased when a stream-level window grows
func (c *connectionFlowController) EnsureMinimumWindowSize(inc protocol.ByteCount) {
	c.mutex.Lock()
	if inc > c.receiveWindowSize {
		c.logger.Debugf("Increasing receive flow control window for the connection to %d kB, in response to stream flow control window increase", c.receiveWindowSize/(1<<10))
		c.receiveWindowSize = utils.MinByteCount(inc, c.maxReceiveWindowSize)
		c.startNewAutoTuningEpoch()
	}
	c.mutex.Unlock()
}
