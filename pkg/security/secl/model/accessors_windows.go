//go:build windows
// +build windows

// Code generated - DO NOT EDIT.
package model

import (
	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
	"net"
	"reflect"
)

func (m *Model) GetIterator(field eval.Field) (eval.Iterator, error) {
	switch field {
	}
	return nil, &eval.ErrIteratorNotSupported{Field: field}
}
func (m *Model) GetEventTypes() []eval.EventType {
	return []eval.EventType{}
}
func (m *Model) GetEvaluator(field eval.Field, regID eval.RegisterID) (eval.Evaluator, error) {
	switch field {
	case "async":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.Async
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	}
	return nil, &eval.ErrFieldNotFound{Field: field}
}
func (ev *Event) GetFields() []eval.Field {
	return []eval.Field{
		"async",
	}
}
func (ev *Event) GetFieldValue(field eval.Field) (interface{}, error) {
	switch field {
	case "async":
		return ev.Async, nil
	}
	return nil, &eval.ErrFieldNotFound{Field: field}
}
func (ev *Event) GetFieldEventType(field eval.Field) (eval.EventType, error) {
	switch field {
	case "async":
		return "*", nil
	}
	return "", &eval.ErrFieldNotFound{Field: field}
}
func (ev *Event) GetFieldType(field eval.Field) (reflect.Kind, error) {
	switch field {
	case "async":
		return reflect.Bool, nil
	}
	return reflect.Invalid, &eval.ErrFieldNotFound{Field: field}
}
func (ev *Event) SetFieldValue(field eval.Field, value interface{}) error {
	switch field {
	case "async":
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Async"}
		}
		ev.Async = rv
		return nil
	}
	return &eval.ErrFieldNotFound{Field: field}
}
