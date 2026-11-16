package core

import "testing"

func TestStateStoreOnChangeFiresOnlyOnChange(t *testing.T) {
	s := NewStateStore()
	var got []RuntimeState
	s.OnChange(func(state RuntimeState, _ string) {
		// 回调里读状态不能死锁
		if current, _ := s.Get(); current != state {
			t.Errorf("回调时状态 %s，期望 %s", current, state)
		}
		got = append(got, state)
	})
	s.Set(StateStarting, "")
	s.Set(StateStarting, "")
	s.Set(StateRunning, "")
	s.Set(StateRunning, "已连接")
	s.Set(StateStopped, "")
	want := []RuntimeState{StateStarting, StateRunning, StateRunning, StateStopped}
	if len(got) != len(want) {
		t.Fatalf("回调次数 %v，期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("回调序列 %v，期望 %v", got, want)
		}
	}
}
