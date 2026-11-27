package fastsax

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"sync/atomic"
)

// This file is the adaptive layer of record mode:
//
//   - detectTag: the RecordConfig.Tag == nil seam of ParseRecords. It buffers
//     the first input window, picks the record tag from the structure and
//     re-feeds the buffered bytes through the normal pipeline (no data loss).
//   - fieldPredictor / scanRecord: a per-worker field-layout predictor. Real
//     record streams repeat the same child-element sequence, so before paying
//     for generic scanMarkup at each '<' the worker memcmp-checks the literal
//     token it saw at the same position in the previous record. A decay
//     counter turns the predictor off for workers that keep missing
//     (shuffled layouts), so the worst case is one branch per record.
//   - RecordStats: atomic counters for scheduler decisions (worker starvation
//     during dispatch, predictor hit rate). ParseRecords only exposes the
//     numbers; actually shedding workers is left to the caller between runs.

// RecordStats collects adaptive-scheduler counters for one ParseRecords run.
// Attach it via RecordConfig.Stats; all fields are atomics and safe to read
// concurrently while the run is in flight.
type RecordStats struct {
	// Dispatches counts groups handed to worker queues, and EmptyDispatch the
	// subset that found the target worker's queue empty. A high ratio means
	// the workers are starved — the run is input-bound (reader or stage-1
	// skeleton), and fewer workers would do the same job.
	Dispatches    atomic.Int64
	EmptyDispatch atomic.Int64

	// PredictHits counts markup tokens emitted through the layout predictor's
	// memcmp fast path; PredictMisses counts learned-position mismatches that
	// fell back to scanMarkup. Workers fold their local counters in when they
	// finish, so totals are exact only after ParseRecords returns.
	PredictHits   atomic.Int64
	PredictMisses atomic.Int64
}

// IOBound reports whether the finished (or in-flight) run looks input-bound:
// more than three quarters of dispatches found an empty worker queue. Callers
// can use it to lower Workers for the next run over the same kind of input;
// ParseRecords itself never sheds live goroutines (this stat is the
// integration point, kept observational to keep the pipeline simple).
func (s *RecordStats) IOBound() bool {
	d := s.Dispatches.Load()
	return d >= 16 && s.EmptyDispatch.Load()*4 > d*3
}

// noteDispatch records one group dispatch. Called only from the stage-1
// goroutine; atomics are for concurrent readers.
func (s *RecordStats) noteDispatch(queueEmpty bool) {
	s.Dispatches.Add(1)
	if queueEmpty {
		s.EmptyDispatch.Add(1)
	}
}

// predictDisabled is a test/bench hook that makes every fieldPredictor start
// disabled, so prediction on/off can be compared through the public API. Only
// toggled between ParseRecords runs.
var predictDisabled atomic.Bool

const (
	predLitMax    = 45      // longest literal worth memcmp-ing; predTok stays 48 bytes
	predMaxToks   = 512     // learned markup positions per record; the tail goes unpredicted
	predCredit0   = 64      // starting miss budget
	predCreditCap = 64      // hits cannot bank credit beyond this (bounds miss streaks)
	predMissCost  = 4       // one miss cancels four hits
	predRecFloor  = 24      // budget restored at each record boundary (~6 misses)
	predProbation = 32      // records before the hit/miss-ratio kill applies
	predPosPaused = 1 << 30 // pos sentinel: prediction paused until the next record
)

// predTok is one learned markup position: the literal token bytes seen there
// in the previous record. n == 0 marks the position unpredictable (token too
// long). Correctness does not depend on what the token contains: the literal
// was returned by scanMarkup as one complete construct, and scanMarkup's
// result is a pure function of the construct's own bytes — so if the input
// matches the literal byte-for-byte, scanMarkup would return exactly
// (len(lit), kind) again, and the fast path is byte-identical by construction.
type predTok struct {
	n    uint8
	kind Kind
	lit  [predLitMax]byte // kept at offset 2, as before nl existed (memcmp alignment)
	nl   uint8            // element-name length of the literal (nameLenTok); fits: n <= predLitMax
}

// fieldPredictor is one worker's layout model: the ordered markup-token
// sequence of the previous record, matched by position. The zero value is
// ready to use (workers just declare one on the stack); state is lazily
// initialized on the first scanRecord call.
//
// Two decay levels keep the miss cost bounded. Within a record, misses drain
// the credit; when it runs out prediction pauses for the rest of that record
// (a single position-shifting field, like an occasional CDATA, cannot rack up
// unbounded misses). Each record boundary restores a small budget floor, and
// after a probation period a worker whose overall misses outweigh hits is
// killed permanently — that is the shuffled-layout path, which then costs one
// branch per record.
type fieldPredictor struct {
	init   bool
	dead   bool // permanently disabled (ratio kill or predictDisabled hook)
	credit int
	pos    int // current markup position within the record; predPosPaused when paused
	recs   int64
	hits   int64
	misses int64
	toks   []predTok
}

// predictNext attempts the fast path for the markup construct at b[0] == '<':
// memcmp the literal learned at this record position. On a hit it returns the
// event geometry directly; on a miss (or an unlearned/unpredictable position)
// the caller falls back to scanMarkup and re-learns via learn.
func (pr *fieldPredictor) predictNext(b []byte) (n int, kind Kind, nl uint8, ok bool) {
	if pr.pos >= len(pr.toks) {
		return 0, 0, 0, false // not learned yet, or paused for this record
	}
	t := &pr.toks[pr.pos]
	if t.n == 0 {
		return 0, 0, 0, false // position learned as unpredictable
	}
	if int(t.n) <= len(b) && bytes.Equal(b[:t.n], t.lit[:t.n]) {
		pr.pos++
		pr.hits++
		if pr.credit < predCreditCap {
			pr.credit++
		}
		return int(t.n), t.kind, t.nl, true
	}
	pr.misses++
	pr.credit -= predMissCost
	if pr.credit <= 0 {
		pr.pos = predPosPaused // out of budget: sit out the rest of this record
	}
	return 0, 0, 0, false
}

// learn records the token scanMarkup actually found at the current position
// (after a predictNext decline) and advances the position. One special case:
// when a tag position instead produced CDATA, a comment or a PI, the token is
// treated as inserted noise (e.g. genxml's occasional CDATA fields) and the
// model position is held back, so the very next token resyncs with the
// learned sequence instead of derailing the rest of the record.
func (pr *fieldPredictor) learn(tok []byte, kind Kind) {
	i := pr.pos
	pr.pos++
	if i >= len(pr.toks) {
		if i >= predMaxToks { // also covers the paused sentinel
			return
		}
		pr.toks = append(pr.toks, predTok{})
	} else if t := &pr.toks[i]; t.n != 0 && t.kind != kind &&
		(kind == KindCData || kind == KindComment || kind == KindPI) {
		pr.pos = i // insertion: keep the position, resync on the next token
		return
	}
	t := &pr.toks[i]
	if len(tok) > predLitMax {
		t.n = 0
		return
	}
	t.n = uint8(len(tok))
	t.kind = kind
	t.nl = uint8(nameLenTok(tok, kind)) // < len(tok) <= predLitMax, always fits
	copy(t.lit[:], tok)
}

// flush folds the predictor's local counters into the run's stats, if any.
// Safe on a nil receiver (predictor disabled via RecordConfig.PredictLayout).
func (pr *fieldPredictor) flush(s *RecordStats) {
	if pr != nil && s != nil {
		s.PredictHits.Add(pr.hits)
		s.PredictMisses.Add(pr.misses)
	}
}

// scanRecord is scanChunk with the field-layout predictor spliced in front of
// scanMarkup. It is called by stage-2 workers on one complete record at a
// time and produces a byte-identical tape either way: prediction hits emit
// exactly the event scanMarkup would have found (see predTok), and everything
// else — text runs, fallbacks, errors, the incomplete-tail cut — mirrors
// scanChunk. pr == nil or a disabled predictor delegates outright.
func scanRecord(data []byte, tape []Event, pr *fieldPredictor) ([]Event, int, error) {
	if pr != nil && !pr.init {
		pr.init = true
		pr.credit = predCredit0
		pr.dead = predictDisabled.Load()
	}
	if pr == nil || pr.dead {
		return scanChunk(data, tape)
	}
	// Record boundary: restore the miss budget floor and apply the probation
	// ratio kill (a layout that keeps missing is not coming back).
	pr.recs++
	if pr.recs > predProbation && pr.hits < 2*pr.misses {
		pr.dead = true
		return scanChunk(data, tape)
	}
	if pr.credit < predRecFloor {
		pr.credit = predRecFloor
	}
	pr.pos = 0
	// A guess-first text scan (remember the previous record's text length per
	// slot, probe data[p+prevLen] for '<', verified by walking the guessed
	// span) was tried here and REJECTED: field values change length from
	// record to record on realistic corpora, so the guess almost never hit,
	// while the per-text-event bookkeeping cost +19% on
	// BenchmarkPredictScanRecord/fixed/predict and +6% on ParseRecords
	// workers=1 (interleaved A/B, M1 Pro). Do not retry without a corpus of
	// truly fixed-width fields.
	p := 0
	for p < len(data) {
		if data[p] != '<' {
			// Text: probe 16 bytes inline (two SWAR words) before paying the
			// IndexByte call, exactly as scanChunk (tiny runs dominate record
			// fields; see the scanChunk text branch and docs/performance.md).
			q := p
			if q+16 <= len(data) {
				x := binary.LittleEndian.Uint64(data[q:]) ^ swarLT
				m := (x - swarLo) &^ x & swarHi
				if m != 0 {
					q += bits.TrailingZeros64(m) >> 3
				} else {
					x = binary.LittleEndian.Uint64(data[q+8:]) ^ swarLT
					m = (x - swarLo) &^ x & swarHi
					if m != 0 {
						q += 8 + bits.TrailingZeros64(m)>>3
					} else if r := bytes.IndexByte(data[q+16:], '<'); r < 0 {
						q = len(data)
					} else {
						q += 16 + r
					}
				}
			} else {
				for q < len(data) && data[q] != '<' {
					q++
				}
			}
			tape = append(tape, Event{Kind: KindText, Start: uint32(p), End: uint32(q)})
			p = q
			if p == len(data) {
				return tape, p, nil
			}
		}
		if n, kind, nl, ok := pr.predictNext(data[p:]); ok {
			tape = append(tape, Event{Kind: kind, nlen: [3]byte{nl},
				Start: uint32(p), End: uint32(p + n)})
			p += n
			continue
		}
		n, kind, err := scanMarkup(data[p:])
		if err != nil {
			return tape, p, err
		}
		if n == 0 { // incomplete: needs more data
			return tape, p, nil
		}
		pr.learn(data[p:p+n], kind)
		tape = append(tape, Event{Kind: kind, nlen: packNameLen(nameLenTok(data[p:p+n], kind)),
			Start: uint32(p), End: uint32(p + n)})
		p += n
	}
	return tape, p, nil
}

// detectTag implements the Tag == nil branch of ParseRecords: it buffers the
// first window (ChunkSize bytes), scans it with scanChunk and picks the first
// element name at depth 1 (a direct child of the root) that starts at least
// twice — or the only depth-1 name, if the window holds fewer than two
// records. Empty names (degenerate tags such as "<>") are never candidates.
// The buffered bytes are re-fed through the returned reader, so the
// pipeline parses the complete input. On success cfg.Tag is set (to a copy)
// and cfg.OnDetect, if any, is invoked with it.
//
// Detection failures deliberately include "Tag is required" in the message:
// the fix is the same as before auto-detection existed — pass an explicit Tag.
func detectTag(r io.Reader, cfg *RecordConfig) (io.Reader, error) {
	ws := cfg.ChunkSize
	if ws <= 0 {
		ws = defaultChunkSize
	}
	buf := make([]byte, ws)
	n, rerr := readChunk(r, buf)
	if rerr != nil && rerr != io.EOF && n == 0 {
		return nil, rerr
	}
	buf = buf[:n]

	skip, err := checkBOM(buf)
	if err != nil {
		return nil, err
	}
	win := buf[skip:]
	tape, cut, serr := scanChunk(win, nil)

	// Walk the tape counting element depth; depth 1 start/self-close events
	// are the record candidates, in first-seen order.
	type candidate struct {
		name  []byte
		count int
	}
	var cands []candidate
	var tag []byte
	note := func(b []byte) []byte {
		name, _ := Name(b)
		if len(name) == 0 {
			// Degenerate tag such as "<>": an empty Tag means "auto-detect"
			// to ParseRecords, so it can never be a record tag.
			return nil
		}
		for i := range cands {
			if bytes.Equal(cands[i].name, name) {
				cands[i].count++
				if cands[i].count == 2 {
					return cands[i].name
				}
				return nil
			}
		}
		cands = append(cands, candidate{name: name, count: 1})
		return nil
	}
	depth := 0
walk:
	for _, e := range tape {
		switch e.Kind {
		case KindStart:
			if depth == 1 {
				if tag = note(win[e.Start:e.End]); tag != nil {
					break walk
				}
			}
			depth++
		case KindSelfClose:
			if depth == 1 {
				if tag = note(win[e.Start:e.End]); tag != nil {
					break walk
				}
			}
		case KindEnd:
			depth--
		}
	}
	if tag == nil {
		switch {
		case len(cands) == 1:
			tag = cands[0].name // fewer than two records in the window
		case serr != nil:
			// Nothing usable and the window is malformed: report that.
			return nil, &SyntaxError{Offset: int64(skip + cut), Msg: serr.Error()}
		case len(cands) == 0:
			return nil, errors.New("fastsax: RecordConfig.Tag is required (auto-detection found no depth-1 element in the first window)")
		default:
			return nil, fmt.Errorf("fastsax: RecordConfig.Tag is required (auto-detection is ambiguous: %d distinct depth-1 elements, none repeated)", len(cands))
		}
	}
	cfg.Tag = append([]byte(nil), tag...) // detach from the detection buffer
	if cfg.OnDetect != nil {
		cfg.OnDetect(cfg.Tag)
	}

	// Re-feed the buffered window ahead of the rest of the input. A non-EOF
	// read error is replayed after the buffered bytes, matching readChunk's
	// "data first, then the error" contract.
	switch rerr {
	case nil:
		return io.MultiReader(bytes.NewReader(buf), r), nil
	case io.EOF:
		return bytes.NewReader(buf), nil
	default:
		return io.MultiReader(bytes.NewReader(buf), errorReader{rerr}), nil
	}
}

// errorReader replays a deferred read error.
type errorReader struct{ err error }

func (e errorReader) Read([]byte) (int, error) { return 0, e.err }
