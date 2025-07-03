package utils

import (
	"fmt"
	"sync/atomic"
	"time"
)

type RoutineMonitor struct {
	Name         string
	NumOfRoutine int64
}

func CreateRoutineMonitor(name string) *RoutineMonitor {
	return &RoutineMonitor{Name: name}
}

func (m *RoutineMonitor) Start() error {
	atomic.AddInt64(&m.NumOfRoutine, 1)
	return nil
}

func (m *RoutineMonitor) Stop() error {
	atomic.AddInt64(&m.NumOfRoutine, -1)
	return nil
}

func (m *RoutineMonitor) String() string {
	str := fmt.Sprintf("%v running routines for %v",
		m.NumOfRoutine, m.Name)
	return str
}

type FuncMonitor struct {
	RoutineM  *RoutineMonitor
	Name      string
	StartTime time.Time
}

func CreateFuncMonitor(name string, r *RoutineMonitor) *FuncMonitor {
	return &FuncMonitor{Name: name, RoutineM: r}
}

func (f *FuncMonitor) Start() error {
	if f.RoutineM != nil {
		f.RoutineM.Start()
	}
	f.StartTime = time.Now()
	return nil
}

func (f *FuncMonitor) Stop() error {
	if f.RoutineM != nil {
		f.RoutineM.Stop()
	}
	return nil
}

func (f *FuncMonitor) String() string {
	elapsedTime := time.Since(f.StartTime)
	str := fmt.Sprintf("%v, take %v with %v",
		f.Name, elapsedTime, f.RoutineM)
	return str
}
