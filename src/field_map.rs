use crate::errors::{
    conditionally_required_field_missing, incorrect_data_format_for_value, other_error,
    MessageRejectErrorTrait,
};
use crate::field::{Field, FieldValueReader};
use crate::fix_boolean::{FIXBoolean, FixBooleanTrait};
use crate::fix_int::{FIXInt, FIXIntTrait};
use crate::fix_utc_timestamp::FIXUTCTimestamp;
use crate::tag::Tag;
use crate::tag_value::TagValue;
use chrono::naive::NaiveDateTime;
use std::collections::HashMap;
use std::sync::RwLock;
use std::vec;

type LocalField = Vec<TagValue>;

fn field_tag(f: LocalField) -> Tag {
    f[0].tag
}

fn init_field(mut f: LocalField, tag: Tag, value: Vec<u8>) {
    f[0].init(tag, value)
}

fn write_field(f: &LocalField, mut buffer: String) {
    for tv in f.iter() {
        buffer.push_str(std::str::from_utf8(&(tv.bytes)).unwrap());
    }
}

// TagOrder true if tag i should occur before tag j
type TagOrder = fn(i: Tag, j: Tag) -> bool;

struct TagSort {
    tags: Vec<Tag>,
    compare: TagOrder,
}

impl TagSort {
    pub fn len(&self) -> isize {
        self.tags.len() as isize
    }
    pub fn swap(&mut self, i: isize, j: isize) {
        self.tags.swap(i as usize, j as usize);
    }

    pub fn less(&self, i: isize, j: isize) -> bool {
        (self.compare)(self.tags[i as usize], self.tags[j as usize])
    }
}

pub struct FieldMapContent {
    tag_lookup: HashMap<Tag, LocalField>,
    tag_sort: TagSort,
}

// FieldMap is a collection of fix fields that make up a fix message.
pub struct FieldMap {
    rw_lock: RwLock<FieldMapContent>,
}

// ascending tags
fn normal_field_order(i: Tag, j: Tag) -> bool {
    i < j
}

impl FieldMap {
    fn init(&mut self) {
        self.init_with_ordering(normal_field_order)
    }

    fn init_with_ordering(&mut self, ordering: TagOrder) {
        let tag_sort = TagSort {
            tags: Vec::new(),
            compare: ordering,
        };
        let field_map_content = FieldMapContent {
            tag_lookup: HashMap::new(),
            tag_sort,
        };
        self.rw_lock = RwLock::new(field_map_content);
    }

    // tags returns all of the Field Tags in this FieldMap
    pub fn tags(&self) -> Vec<Tag> {
        let rlock_result = self.rw_lock.read();
        if rlock_result.is_err() {
            return vec![];
        }
        rlock_result.unwrap().tag_sort.tags.to_vec()
    }

    // get parses out a field in this FieldMap. Returned reject may indicate the field is not present, or the field value is invalid.
    pub fn get<P: Field + FieldValueReader>(
        &self,
        parser: P,
    ) -> Result<(), Box<dyn MessageRejectErrorTrait>> {
        self.get_field(parser.tag(), parser)
    }

    // has returns true if the Tag is present in this FieldMap
    pub fn has(&self, tag: Tag) -> bool {
        let rlock_result = self.rw_lock.read();
        if rlock_result.is_err() {
            return false;
        }
        rlock_result.unwrap().tag_lookup.get(&tag).is_some()
    }

    // get_field parses of a field with Tag tag. Returned reject may indicate the field is not present, or the field value is invalid.
    pub fn get_field<P: FieldValueReader>(
        &self,
        tag: Tag,
        mut parser: P,
    ) -> Result<(), Box<dyn MessageRejectErrorTrait>> {
        let rlock = self.rw_lock.read().map_err(|_| other_error())?;
        let f = rlock
            .tag_lookup
            .get(&tag)
            .ok_or(conditionally_required_field_missing(tag))?;

        parser
            .read(&String::from_utf8_lossy(&f[0].value))
            .map_err(|_| incorrect_data_format_for_value(tag))?;

        Ok(())
    }

    // get_bytes is a zero-copy get_field wrapper for []bytes fields
    pub fn get_bytes(&self, tag: Tag) -> Result<String, Box<dyn MessageRejectErrorTrait>> {
        let rlock = self.rw_lock.read().map_err(|_| other_error())?;
        let f = rlock
            .tag_lookup
            .get(&tag)
            .ok_or(conditionally_required_field_missing(tag))?;
        Ok(String::from_utf8_lossy(&f[0].value).to_string())
    }

    // get_bool is a get_field wrapper for bool fields
    pub fn get_bool(&self, tag: Tag) -> Result<bool, Box<dyn MessageRejectErrorTrait>> {
        let val = FIXBoolean::default();
        let _ = self.get_field(tag, val)?;
        Ok(val.bool())
    }

    // get_int is a get_field wrapper for int fields
    pub fn get_int(&self, tag: Tag) -> Result<isize, Box<dyn MessageRejectErrorTrait>> {
        let mut val = FIXInt::default();
        let bytes = self.get_bytes(tag)?;

        let _ = val
            .read(&bytes)
            .map_err(|_| incorrect_data_format_for_value(tag));

        Ok(val.int())
    }

    // get_time is a get_field wrapper for utc timestamp fields
    pub fn get_time(&self, tag: Tag) -> Result<NaiveDateTime, Box<dyn MessageRejectErrorTrait>> {
        let mut val = FIXUTCTimestamp::default();
        let bytes = self.get_bytes(tag)?;

        let _ = val
            .read(&bytes)
            .map_err(|_| incorrect_data_format_for_value(tag));

        Ok(val.time)
    }

    // //GetString is a get_field wrapper for string fields
    // fn (m FieldMap) GetString(tag Tag) (string, MessageRejectError) {
    // 	var val FIXString
    // 	if err := m.get_field(tag, &val); err != nil {
    // 		return "", err
    // 	}
    // 	return string(val), nil
    // }

    // //GetGroup is a Get fntion specific to Group Fields.
    // fn (m FieldMap) GetGroup(parser FieldGroupReader) MessageRejectError {
    // 	m.rwLock.RLock()
    // 	defer m.rwLock.RUnlock()

    // 	f, ok := m.tagLookup[parser.Tag()]
    // 	if !ok {
    // 		return ConditionallyRequiredFieldMissing(parser.Tag())
    // 	}

    // 	if _, err := parser.Read(f); err != nil {
    // 		if msgRejErr, ok := err.(MessageRejectError); ok {
    // 			return msgRejErr
    // 		}
    // 		return IncorrectDataFormatForValue(parser.Tag())
    // 	}

    // 	return nil
    // }

    // //SetField sets the field with Tag tag
    // fn (m *FieldMap) SetField(tag Tag, field FieldValueWriter) *FieldMap {
    // 	return m.SetBytes(tag, field.Write())
    // }

    // //SetBytes sets bytes
    // fn (m *FieldMap) SetBytes(tag Tag, value []byte) *FieldMap {
    // 	f := m.getOrCreate(tag)
    // 	init_field(f, tag, value)
    // 	return m
    // }

    // //SetBool is a SetField wrapper for bool fields
    // fn (m *FieldMap) SetBool(tag Tag, value bool) *FieldMap {
    // 	return m.SetField(tag, FIXBoolean(value))
    // }

    // //SetInt is a SetField wrapper for int fields
    // fn (m *FieldMap) SetInt(tag Tag, value int) *FieldMap {
    // 	v := FIXInt(value)
    // 	return m.SetBytes(tag, v.Write())
    // }

    // //SetString is a SetField wrapper for string fields
    // fn (m *FieldMap) SetString(tag Tag, value string) *FieldMap {
    // 	return m.SetBytes(tag, []byte(value))
    // }

    // //Clear purges all fields from field map
    // fn (m *FieldMap) Clear() {
    // 	m.rwLock.Lock()
    // 	defer m.rwLock.Unlock()

    // 	m.tags = m.tags[0:0]
    // 	for k := range m.tagLookup {
    // 		delete(m.tagLookup, k)
    // 	}
    // }

    // //CopyInto overwrites the given FieldMap with this one
    // fn (m *FieldMap) CopyInto(to *FieldMap) {
    // 	m.rwLock.RLock()
    // 	defer m.rwLock.RUnlock()

    // 	to.tagLookup = make(map[Tag]field)
    // 	for tag, f := range m.tagLookup {
    // 		clone := make(field, 1)
    // 		clone[0] = f[0]
    // 		to.tagLookup[tag] = clone
    // 	}
    // 	to.tags = make([]Tag, len(m.tags))
    // 	copy(to.tags, m.tags)
    // 	to.compare = m.compare
    // }

    // fn (m *FieldMap) add(f field) {
    // 	m.rwLock.Lock()
    // 	defer m.rwLock.Unlock()

    // 	t := field_tag(f)
    // 	if _, ok := m.tagLookup[t]; !ok {
    // 		m.tags = append(m.tags, t)
    // 	}

    // 	m.tagLookup[t] = f
    // }

    // fn (m *FieldMap) getOrCreate(tag Tag) field {
    // 	m.rwLock.Lock()
    // 	defer m.rwLock.Unlock()

    // 	if f, ok := m.tagLookup[tag]; ok {
    // 		f = f[:1]
    // 		return f
    // 	}

    // 	f := make(field, 1)
    // 	m.tagLookup[tag] = f
    // 	m.tags = append(m.tags, tag)
    // 	return f
    // }

    // //Set is a setter for fields
    // fn (m *FieldMap) Set(field FieldWriter) *FieldMap {
    // 	f := m.getOrCreate(field.Tag())
    // 	init_field(f, field.Tag(), field.Write())
    // 	return m
    // }

    // //SetGroup is a setter specific to group fields
    // fn (m *FieldMap) SetGroup(field FieldGroupWriter) *FieldMap {
    // 	m.rwLock.Lock()
    // 	defer m.rwLock.Unlock()

    // 	_, ok := m.tagLookup[field.Tag()]
    // 	if !ok {
    // 		m.tags = append(m.tags, field.Tag())
    // 	}
    // 	m.tagLookup[field.Tag()] = field.Write()
    // 	return m
    // }

    // fn (m *FieldMap) sortedTags() []Tag {
    // 	sort.Sort(m)
    // 	return m.tags
    // }

    // fn (m FieldMap) write(buffer *bytes.Buffer) {
    // 	m.rwLock.Lock()
    // 	defer m.rwLock.Unlock()

    // 	for _, tag := range m.sortedTags() {
    // 		if f, ok := m.tagLookup[tag]; ok {
    // 			write_field(f, buffer)
    // 		}
    // 	}
    // }

    // fn (m FieldMap) total() int {
    // 	m.rwLock.RLock()
    // 	defer m.rwLock.RUnlock()

    // 	total := 0
    // 	for _, fields := range m.tagLookup {
    // 		for _, tv := range fields {
    // 			switch tv.tag {
    // 			case tagCheckSum: //tag does not contribute to total
    // 			default:
    // 				total += tv.total()
    // 			}
    // 		}
    // 	}

    // 	return total
    // }

    // fn (m FieldMap) length() int {
    // 	m.rwLock.RLock()
    // 	defer m.rwLock.RUnlock()

    // 	length := 0
    // 	for _, fields := range m.tagLookup {
    // 		for _, tv := range fields {
    // 			switch tv.tag {
    // 			case tagBeginString, tagBodyLength, tagCheckSum: //tags do not contribute to length
    // 			default:
    // 				length += tv.length()
    // 			}
    // 		}
    // 	}

    // 	return length
    // }
}

// ----- test
//

// import (
// 	"bytes"
// 	"testing"

// 	"github.com/stretchr/testify/assert"
// )

// fn TestFieldMap_Clear(t *testing.T) {
// 	var fMap FieldMap
// 	fMap.init()

// 	fMap.SetField(1, FIXString("hello"))
// 	fMap.SetField(2, FIXString("world"))

// 	fMap.Clear()

// 	if fMap.Has(1) || fMap.Has(2) {
// 		t.Error("All fields should be cleared")
// 	}
// }

// fn TestFieldMap_SetAndGet(t *testing.T) {
// 	var fMap FieldMap
// 	fMap.init()

// 	fMap.SetField(1, FIXString("hello"))
// 	fMap.SetField(2, FIXString("world"))

// 	var testCases = []struct {
// 		tag         Tag
// 		expectErr   bool
// 		expectValue string
// 	}{
// 		{tag: 1, expectValue: "hello"},
// 		{tag: 2, expectValue: "world"},
// 		{tag: 44, expectErr: true},
// 	}

// 	for _, tc := range testCases {
// 		var testField FIXString
// 		err := fMap.get_field(tc.tag, &testField)

// 		if tc.expectErr {
// 			assert.NotNil(t, err, "Expected Error")
// 			continue
// 		}

// 		assert.Nil(t, err, "Unexpected error")
// 		assert.Equal(t, tc.expectValue, string(testField))
// 	}
// }

// fn TestFieldMap_Length(t *testing.T) {
// 	var fMap FieldMap
// 	fMap.init()
// 	fMap.SetField(1, FIXString("hello"))
// 	fMap.SetField(2, FIXString("world"))
// 	fMap.SetField(8, FIXString("FIX.4.4"))
// 	fMap.SetField(9, FIXInt(100))
// 	fMap.SetField(10, FIXString("100"))
// 	assert.Equal(t, 16, fMap.length(), "Length should include all fields but beginString, bodyLength, and checkSum")
// }

// fn TestFieldMap_Total(t *testing.T) {

// 	var fMap FieldMap
// 	fMap.init()
// 	fMap.SetField(1, FIXString("hello"))
// 	fMap.SetField(2, FIXString("world"))
// 	fMap.SetField(8, FIXString("FIX.4.4"))
// 	fMap.SetField(Tag(9), FIXInt(100))
// 	fMap.SetField(10, FIXString("100"))

// 	assert.Equal(t, 2116, fMap.total(), "Total should includes all fields but checkSum")
// }

// fn TestFieldMap_TypedSetAndGet(t *testing.T) {
// 	var fMap FieldMap
// 	fMap.init()

// 	fMap.SetString(1, "hello")
// 	fMap.SetInt(2, 256)

// 	s, err := fMap.GetString(1)
// 	assert.Nil(t, err)
// 	assert.Equal(t, "hello", s)

// 	i, err := fMap.get_int(2)
// 	assert.Nil(t, err)
// 	assert.Equal(t, 256, i)

// 	_, err = fMap.get_int(1)
// 	assert.NotNil(t, err, "Type mismatch should occur error")

// 	s, err = fMap.GetString(2)
// 	assert.Nil(t, err)
// 	assert.Equal(t, "256", s)

// 	b, err := fMap.get_bytes(1)
// 	assert.Nil(t, err)
// 	assert.True(t, bytes.Equal([]byte("hello"), b))
// }

// fn TestFieldMap_BoolTypedSetAndGet(t *testing.T) {
// 	var fMap FieldMap
// 	fMap.init()

// 	fMap.SetBool(1, true)
// 	v, err := fMap.get_bool(1)
// 	assert.Nil(t, err)
// 	assert.True(t, v)

// 	s, err := fMap.GetString(1)
// 	assert.Nil(t, err)
// 	assert.Equal(t, "Y", s)

// 	fMap.SetBool(2, false)
// 	v, err = fMap.get_bool(2)
// 	assert.Nil(t, err)
// 	assert.False(t, v)

// 	s, err = fMap.GetString(2)
// 	assert.Nil(t, err)
// 	assert.Equal(t, "N", s)
// }

// fn TestFieldMap_CopyInto(t *testing.T) {
// 	var fMapA FieldMap
// 	fMapA.init_with_ordering(headerFieldOrdering)
// 	fMapA.SetString(9, "length")
// 	fMapA.SetString(8, "begin")
// 	fMapA.SetString(35, "msgtype")
// 	fMapA.SetString(1, "a")
// 	assert.Equal(t, []Tag{8, 9, 35, 1}, fMapA.sortedTags())

// 	var fMapB FieldMap
// 	fMapB.init()
// 	fMapB.SetString(1, "A")
// 	fMapB.SetString(3, "C")
// 	fMapB.SetString(4, "D")
// 	assert.Equal(t, fMapB.sortedTags(), []Tag{1, 3, 4})

// 	fMapA.CopyInto(&fMapB)

// 	assert.Equal(t, []Tag{8, 9, 35, 1}, fMapB.sortedTags())

// 	// new fields
// 	s, err := fMapB.GetString(35)
// 	assert.Nil(t, err)
// 	assert.Equal(t, "msgtype", s)

// 	// existing fields overwritten
// 	s, err = fMapB.GetString(1)
// 	assert.Nil(t, err)
// 	assert.Equal(t, "a", s)

// 	// old fields cleared
// 	_, err = fMapB.GetString(3)
// 	assert.NotNil(t, err)

// 	// check that ordering is overwritten
// 	fMapB.SetString(2, "B")
// 	assert.Equal(t, []Tag{8, 9, 35, 1, 2}, fMapB.sortedTags())

// 	// updating the existing map doesn't affect the new
// 	fMapA.init()
// 	fMapA.SetString(1, "AA")
// 	s, err = fMapB.GetString(1)
// 	assert.Nil(t, err)
// 	assert.Equal(t, "a", s)
// 	fMapA.Clear()
// 	s, err = fMapB.GetString(1)
// 	assert.Nil(t, err)
// 	assert.Equal(t, "a", s)
// }
