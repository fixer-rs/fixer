// EventTimerFunc true if tag i should occur before tag j
type EventTimerFunc = fn();

pub struct EventTimer {
    f: EventTimerFunc,
}

// TODO
