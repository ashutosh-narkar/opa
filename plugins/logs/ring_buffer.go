package logs

type ringBuffer struct {
	inputChannel  chan *ringBufferElem
	outputChannel chan *ringBufferElem
	limit         int64
}

type ringBufferElem struct {
	bs []byte
}

func newRingBuffer(limit int64) *ringBuffer {
	return &ringBuffer{
		inputChannel:  make(chan *ringBufferElem),
		outputChannel: make(chan *ringBufferElem, limit),
	}
}

func (rb *ringBuffer) Run() {
	// range on input will get elements or block until input channel is closed
	for v := range rb.inputChannel {
		select {
		// output has some space
		case rb.outputChannel <- v:
		default:
			// output doesn't have space, discard the oldest one to put one
			<-rb.outputChannel
			rb.outputChannel <- v
		}
	}
	// input channel is closed so close the output channel as well
	close(rb.outputChannel)
}

func (rb *ringBuffer) Push(bs []byte) {
	rb.inputChannel <- &ringBufferElem{bs: bs}
}

func (rb *ringBuffer) Read() <-chan *ringBufferElem {
	return rb.outputChannel
}

func (rb *ringBuffer) Close() {
	close(rb.inputChannel)
}
