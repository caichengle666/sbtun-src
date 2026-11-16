package core

import "sync"

// RuntimeState 描述 sbtun 当前运行状态。
type RuntimeState string

const (
	StateStopped  RuntimeState = "stopped"
	StateStarting RuntimeState = "starting"
	StateRunning  RuntimeState = "running"
	StateStopping RuntimeState = "stopping"
	StateError    RuntimeState = "error"
)

// StateStore 为 GUI、托盘和核心模块提供统一状态来源。
type StateStore struct {
	mu       sync.RWMutex
	state    RuntimeState
	err      string
	onChange func(RuntimeState, string)
}

func NewStateStore() *StateStore {
	return &StateStore{state: StateStopped}
}

func (s *StateStore) Set(state RuntimeState, err string) {
	s.mu.Lock()
	changed := s.state != state || s.err != err
	s.state = state
	s.err = err
	notify := s.onChange
	s.mu.Unlock()
	// 回调在锁外执行，回调里再读状态不会死锁。
	if changed && notify != nil {
		notify(state, err)
	}
}

// OnChange 登记状态变化回调（只保留最后一个），界面用它在状态变化时立即刷新，不必等轮询。
func (s *StateStore) OnChange(fn func(RuntimeState, string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onChange = fn
}

func (s *StateStore) Get() (RuntimeState, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state, s.err
}

func (s *StateStore) IsRunning() bool {
	state, _ := s.Get()
	return state == StateRunning
}
