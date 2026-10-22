package yabber

import "reflect"

// Clone returns a deep copy of c that shares no slices, maps or pointers
// with it.
func (c Config) Clone() Config {
	return deepCopy(reflect.ValueOf(c)).Interface().(Config)
}

func deepCopy(value reflect.Value) reflect.Value {
	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() {
			return value
		}
		result := reflect.New(value.Type().Elem())
		result.Elem().Set(deepCopy(value.Elem()))
		return result
	case reflect.Slice:
		if value.IsNil() {
			return value
		}
		result := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		for i := range value.Len() {
			result.Index(i).Set(deepCopy(value.Index(i)))
		}
		return result
	case reflect.Map:
		if value.IsNil() {
			return value
		}
		result := reflect.MakeMapWithSize(value.Type(), value.Len())
		for iter := value.MapRange(); iter.Next(); {
			result.SetMapIndex(iter.Key(), deepCopy(iter.Value()))
		}
		return result
	case reflect.Interface:
		if value.IsNil() {
			return value
		}
		result := reflect.New(value.Type()).Elem()
		result.Set(deepCopy(value.Elem()))
		return result
	case reflect.Struct:
		result := reflect.New(value.Type()).Elem()
		for i := range value.NumField() {
			if result.Field(i).CanSet() {
				result.Field(i).Set(deepCopy(value.Field(i)))
			}
		}
		return result
	default:
		return value
	}
}
