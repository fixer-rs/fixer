use crate::session::session_id::SessionID;

pub fn session_id_filename_prefix(s: &SessionID) -> String {
    let mut sender = vec![s.sender_comp_id.as_str()];
    if !s.sender_sub_id.is_empty() {
        sender.push(s.sender_sub_id.as_str());
    }
    if !s.sender_location_id.is_empty() {
        sender.push(s.sender_location_id.as_str());
    }

    let mut target = vec![s.target_comp_id.as_str()];
    if !s.target_sub_id.is_empty() {
        target.push(s.target_sub_id.as_str());
    }
    if !s.target_location_id.is_empty() {
        target.push(s.target_location_id.as_str());
    }

    let sender_str = &sender.join("_");
    let target_str = &target.join("_");

    let mut fname = vec![s.begin_string.as_str(), sender_str, target_str];

    if !s.qualifier.is_empty() {
        fname.push(s.qualifier.as_str());
    }

    fname.join("-")
}

// close_file behaves like Close, except that no error is returned if the file does not exist.
// fn close_file(f *os.File) error {
// 	if f != nil {
// 		if err := f.Close(); err != nil {
// 			if !os.IsNotExist(err) {
// 				return err
// 			}
// 		}
// 	}
// 	return nil
// }

// remove_file behaves like os.Remove, except that no error is returned if the file does not exist.
// fn remove_file(fname string) error {
// 	if err := os.Remove(fname); (err != nil) && !os.IsNotExist(err) {
// 		return errors.Wrapf(err, "remove %v", fname)
// 	}
// 	return nil
// }

// open_or_create_file opens a file for reading and writing, creating it if necessary.
// fn open_or_create_file(fname string, perm os.FileMode) (f *os.File, err error) {
// 	if f, err = os.OpenFile(fname, os.O_RDWR, perm); err != nil {
// 		if f, err = os.OpenFile(fname, os.O_RDWR|os.O_CREATE, perm); err != nil {
// 			return nil, fmt.Errorf("error opening or creating file: %s: %s", fname, err.Error())
// 		}
// 	}
// 	return f, nil
// }

#[cfg(test)]
mod tests {
    // fn require_not_file_exists(t *testing.T, fname string) {
    // 	_, err := os.Stat(fname)
    // 	require.NotNil(t, err)
    // 	require.True(t, os.IsNotExist(err))
    // }

    // fn require_file_exists(t *testing.T, fname string) {
    // 	_, err := os.Stat(fname)
    // 	require.Nil(t, err)
    // }

    use crate::{fileutil::session_id_filename_prefix, session::session_id::SessionID};

    #[test]
    fn test_session_id_filename_minimally_qualified_session_id() {
        // When the session ID is
        let session_id = SessionID {
            begin_string: "FIX.4.4".to_string(),
            sender_comp_id: "SENDER".to_string(),
            target_comp_id: "TARGET".to_string(),
            ..Default::default()
        };

        // Then the filename should be
        assert_eq!(
            "FIX.4.4-SENDER-TARGET",
            session_id_filename_prefix(&session_id)
        );
    }

    #[test]
    fn test_session_id_filename_fully_qualified_session_id() {
        // When the session ID is
        let session_id = SessionID {
            begin_string: "FIX.4.4".to_string(),
            sender_comp_id: "A".to_string(),
            sender_sub_id: "B".to_string(),
            sender_location_id: "C".to_string(),
            target_comp_id: "D".to_string(),
            target_sub_id: "E".to_string(),
            target_location_id: "F".to_string(),
            qualifier: "G".to_string(),
        };

        // Then the filename should be
        assert_eq!(
            "FIX.4.4-A_B_C-D_E_F-G",
            session_id_filename_prefix(&session_id)
        );
    }

    // fn TestOpenOrCreateFile(t *testing.T) {
    // 	// When the file doesn't exist yet
    // 	fname := path.Join(os.TempDir(), fmt.Sprintf("TestOpenOrCreateFile-%d", os.Getpid()))
    // 	require_not_file_exists(t, fname)
    // 	defer os.Remove(fname)

    // 	// Then it should be created
    // 	f, err := open_or_create_file(fname, 0664)
    // 	require.Nil(t, err)
    // 	require_file_exists(t, fname)

    // 	// When the file already exists
    // 	f.Close()

    // 	// Then it should be opened
    // 	f, err = open_or_create_file(fname, 0664)
    // 	require.Nil(t, err)
    // 	require.Nil(t, f.Close())
    // }
}
