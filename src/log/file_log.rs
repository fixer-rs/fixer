use crate::{
    log::{LogFactoryTrait, LogTrait},
    session::session_id::SessionID,
};
use flexi_logger::LoggerHandle;
use log::info;
use ramhorns::Template;
use std::collections::HashMap;

pub struct FileLog {
    event_logger: LoggerHandle,
    message_logger: LoggerHandle,
}

impl LogTrait for FileLog {
    fn on_incoming(&self, data: &[u8]) {
        info!(
            target: "message_logger",
            "{}",
            String::from_utf8_lossy(data),
        )
    }

    fn on_outgoing(&self, data: &[u8]) {
        info!(
            target: "message_logger",
            "{}",
            String::from_utf8_lossy(data),
        )
    }

    fn on_event(&self, data: &str) {
        info!(
            target: "event_logger",
            "{}",
            data,
        )
    }

    fn on_eventf(&self, fmt: &str, params: HashMap<String, String>) {
        let tpl = Template::new(fmt).unwrap();
        self.on_event(&tpl.render(&params));
    }
}

pub struct FileLogFactory {
    global_log_path: String,
    session_log_paths: HashMap<SessionID, String>, // TODO: convert this to &SessionID
}
impl FileLogFactory {
    // new creates an instance of LogFactory that writes messages and events to file.
    // The location of global and session log files is configured via FileLogPath.
    // fn new(settings *Settings) -> Result<dyn LogFactory>, Box<dyn Error> {
    // 	logFactory := fileLogFactory{}

    // 	var err error
    // 	if logFactory.global_log_path, err = settings.GlobalSettings().Setting(config.FileLogPath); err != nil {
    // 		return logFactory, err
    // 	}

    // 	logFactory.session_log_paths = make(map[SessionID]string)

    // 	for sid, sessionSettings := range settings.SessionSettings() {
    // 		logPath, err := sessionSettings.Setting(config.FileLogPath)
    // 		if err != nil {
    // 			return logFactory, err
    // 		}
    // 		logFactory.session_log_paths[sid] = logPath
    // 	}

    // 	return logFactory, nil
    // }
}

// func newFileLog(prefix string, logPath string) (fileLog, error) {
// 	l := fileLog{}

// 	eventLogName := path.Join(logPath, prefix+".event.current.log")
// 	messageLogName := path.Join(logPath, prefix+".messages.current.log")

// 	if err := os.MkdirAll(logPath, os.ModePerm); err != nil {
// 		return l, err
// 	}

// 	fileFlags := os.O_RDWR | os.O_CREATE | os.O_APPEND
// 	eventFile, err := os.OpenFile(eventLogName, fileFlags, os.ModePerm)
// 	if err != nil {
// 		return l, err
// 	}

// 	messageFile, err := os.OpenFile(messageLogName, fileFlags, os.ModePerm)
// 	if err != nil {
// 		return l, err
// 	}

// 	logFlag := log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC
// 	l.eventLogger = log.New(eventFile, "", logFlag)
// 	l.messageLogger = log.New(messageFile, "", logFlag)

// 	return l, nil
// }

// func (f fileLogFactory) Create() (Log, error) {
// 	return newFileLog("GLOBAL", f.global_log_path)
// }

// func (f fileLogFactory) CreateSessionLog(sessionID SessionID) (Log, error) {
// 	logPath, ok := f.session_log_paths[sessionID]

// 	if !ok {
// 		return nil, fmt.Errorf("logger not defined for %v", sessionID)
// 	}

// 	prefix := sessionIDFilenamePrefix(sessionID)
// 	return newFileLog(prefix, logPath)
// }

#[cfg(test)]
mod tests {

    // package quickfix

    // import (
    // 	"bufio"
    // 	"fmt"
    // 	"os"
    // 	"path"
    // 	"strings"
    // 	"testing"
    // )

    // func TestFileLog_FileLogFactory::new(t *testing.T) {

    // 	_, err := FileLogFactory::new(NewSettings())

    // 	if err == nil {
    // 		t.Error("Should expect error when settings have no file log path")
    // 	}

    // 	cfg := `
    // # default settings for sessions
    // [DEFAULT]
    // ConnectionType=initiator
    // ReconnectInterval=60
    // SenderCompID=TW
    // FileLogPath=.

    // # session definition
    // [SESSION]
    // BeginString=FIX.4.1
    // TargetCompID=ARCA
    // FileLogPath=mydir

    // [SESSION]
    // BeginString=FIX.4.1
    // TargetCompID=ARCA
    // SessionQualifier=BS
    // `
    // 	stringReader := strings.NewReader(cfg)
    // 	settings, _ := ParseSettings(stringReader)

    // 	factory, err := FileLogFactory::new(settings)

    // 	if err != nil {
    // 		t.Error("Did not expect error", err)
    // 	}

    // 	if factory == nil {
    // 		t.Error("Should have returned factory")
    // 	}
    // }

    // type fileLogHelper struct {
    // 	LogPath string
    // 	Prefix  string
    // 	Log     Log
    // }

    // func newFileLogHelper(t *testing.T) *fileLogHelper {
    // 	prefix := "myprefix"
    // 	logPath := path.Join(os.TempDir(), fmt.Sprintf("TestLogStore-%d", os.Getpid()))

    // 	log, err := newFileLog(prefix, logPath)
    // 	if err != nil {
    // 		t.Error("Unexpected error", err)
    // 	}

    // 	return &fileLogHelper{
    // 		LogPath: logPath,
    // 		Prefix:  prefix,
    // 		Log:     log,
    // 	}
    // }

    // func TestNewFileLog(t *testing.T) {
    // 	helper := newFileLogHelper(t)

    // 	tests := []struct {
    // 		expectedPath string
    // 	}{
    // 		{path.Join(helper.LogPath, fmt.Sprintf("%v.messages.current.log", helper.Prefix))},
    // 		{path.Join(helper.LogPath, fmt.Sprintf("%v.event.current.log", helper.Prefix))},
    // 	}

    // 	for _, test := range tests {
    // 		if _, err := os.Stat(test.expectedPath); os.IsNotExist(err) {
    // 			t.Errorf("%v does not exist", test.expectedPath)
    // 		}
    // 	}
    // }

    // func TestFileLog_Append(t *testing.T) {
    // 	helper := newFileLogHelper(t)

    // 	messageLogFile, err := os.Open(path.Join(helper.LogPath, fmt.Sprintf("%v.messages.current.log", helper.Prefix)))
    // 	if err != nil {
    // 		t.Error("Unexpected error", err)
    // 	}
    // 	defer messageLogFile.Close()

    // 	eventLogFile, err := os.Open(path.Join(helper.LogPath, fmt.Sprintf("%v.event.current.log", helper.Prefix)))
    // 	if err != nil {
    // 		t.Error("Unexpected error", err)
    // 	}
    // 	defer eventLogFile.Close()

    // 	messageScanner := bufio.NewScanner(messageLogFile)
    // 	eventScanner := bufio.NewScanner(eventLogFile)

    // 	helper.Log.OnIncoming([]byte("incoming"))
    // 	if !messageScanner.Scan() {
    // 		t.Error("Unexpected EOF")
    // 	}

    // 	helper.Log.OnEvent("Event")
    // 	if !eventScanner.Scan() {
    // 		t.Error("Unexpected EOF")
    // 	}

    // 	newHelper := newFileLogHelper(t)
    // 	newHelper.Log.OnIncoming([]byte("incoming"))
    // 	if !messageScanner.Scan() {
    // 		t.Error("Unexpected EOF")
    // 	}

    // 	newHelper.Log.OnEvent("Event")
    // 	if !eventScanner.Scan() {
    // 		t.Error("Unexpected EOF")
    // 	}
    // }
}
