//FIXString is a FIX String Value, implements FieldValue
type FIXString = String;

pub trait FixStringTrait {
    fn read(&mut self, bytes: &[u8]) -> String;
}

// func (f *FIXString) Read(bytes []byte) (err error) {
// 	*f = FIXString(bytes)
// 	return
// }

// func (f FIXString) Write() []byte {
// 	return []byte(f)
// }
