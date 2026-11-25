// Hardware-independent replay engine.
//
// Drives the protocol package's OWN reassembler and decoders over synthetic
// notifications and the frozen public parity oracle. No BLE, no filesystem
// writes outside the supplied report path, no device pairing, no token handling.

import 'dart:convert';
import 'dart:io';

import 'package:openstrap_protocol/openstrap_protocol.dart';

const String decoderVersion = 'protocol@fbadb5b';

Map<String, dynamic> _readJson(String path) =>
    json.decode(File(path).readAsStringSync()) as Map<String, dynamic>;

List<dynamic> _readJsonList(String path) =>
    json.decode(File(path).readAsStringSync()) as List<dynamic>;

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// Structural comparison used by the frozen parity oracle. Mirrors
/// protocol/test/parity_test.dart but is independent of its assertion wiring.
String? _diff(dynamic actual, dynamic expected, String path) {
  if (expected == null) {
    return actual == null ? null : 'at $path: expected null, got ${json.encode(actual)}';
  }
  if (actual == null) return 'at $path: expected ${json.encode(expected)}, got null';
  if (expected is Map && actual is Map) {
    for (final key in expected.keys) {
      final d = _diff(actual[key], expected[key], '$path.$key');
      if (d != null) return d;
    }
    const allowedExtras = {'xs', 'ys', 'zs'};
    for (final key in actual.keys) {
      if (!expected.containsKey(key) && !allowedExtras.contains(key)) {
        return 'at $path.$key: unexpected extra key (value ${actual[key]})';
      }
    }
    return null;
  }
  if (expected is List && actual is List) {
    if (expected.length != actual.length) {
      return 'at $path: length ${actual.length} != ${expected.length}';
    }
    for (var i = 0; i < expected.length; i++) {
      final d = _diff(actual[i], expected[i], '$path[$i]');
      if (d != null) return d;
    }
    return null;
  }
  if (expected is num && actual is num) {
    return expected == actual ? null : 'at $path: $actual != $expected';
  }
  return expected == actual ? null : 'at $path: ${json.encode(actual)} != ${json.encode(expected)}';
}

dynamic _decodeParityKind(String kind, String hex) {
  switch (kind) {
    case 'r24':
      return parseR24(hexToBytes(hex))?.toMap();
    case 'record':
      return decodeRecord(hex)?.toMap();
    case 'rr':
      return realtimeRr(hex)?.toMap();
    case 'accel':
      return frameAccel(hex)?.toMap();
    default:
      throw StateError('unknown parity kind: $kind');
  }
}

Map<String, dynamic> _frameView(Frame frame, int index, String fixtureId) {
  final version = frame.inner.length > 1 ? frame.inner[1] : -1;
  return {
    'frameIndex': index,
    'innerHex': _hex(frame.inner),
    'headerCrcOk': frame.headerCrcOk,
    'crc32Ok': frame.crc32Ok,
    'valid': frame.valid,
    'decodable': frame.decodable,
    'truncated': frame.truncated,
    'packetType': frame.packetType,
    'opcode': frame.opcode,
    'recordVersion': version,
    'rawFrameRef': 'fixtures/synthetic/$fixtureId.json#frame-$index',
  };
}

/// Canonical samples are deliberately sealed: no SpO2, temperature, stage or
/// score reaches this object. Everything is diagnostics-only until real
/// participant-disjoint validation promotes a field in docs/COVERAGE.md.
Map<String, dynamic> _canonicalSample(
  String family,
  String fixtureId,
  Map<String, dynamic> view,
  Map<String, dynamic> caseData,
  List<Frame> frames,
  int index,
) {
  final base = {
    'family': family,
    'deviceId': 'local-pseudonymous-id',
    'firmware': 'unspecified-synthetic',
    'recordVersion': view['recordVersion'],
    'sourceCaptureId': fixtureId,
    'decoderVersion': decoderVersion,
    'rawFrameRef': view['rawFrameRef'],
    'confidence': 'raw',
    // Offsets are ledger-fixed: epoch seconds at inner[7:11] and a Q15
    // fractional second at inner[11:13] (raw/32768), never a local-time
    // reinterpretation. No field reaches a user-facing trend by default.
    'timestampConvention': 'unix_seconds + q15_subsec/32768',
    'exposureAllowed': false,
  };
  var kind = caseData['recordKind'] as String? ?? 'unknown';
  final version = view['recordVersion'] as int;
  final packetType = view['packetType'] as int;
  final opcode = view['opcode'] as int;
  if (packetType == 0x23 && opcode == 0x17) kind = 'history_end';

  if (kind == 'history_end') {
    return {
      ...base,
      'kind': 'history_end',
      'ackEligible': false,
      'ackGate': 'commit-before-ACK ledger required; replay cannot construct an ACK token',
      'historyComplete': caseData['historyComplete'] == true,
      'backlogRemaining': caseData['backlogRemaining'] == true,
    };
  }
  if (version == 25) {
    // v25 is timestamp + raw PPG burst only. No gravity/HR/SpO2/stage.
    return {
      ...base,
      'kind': 'w4_v25_raw',
      'fields': {
        'timestamp_bytes': view['innerHex'].substring(14, 22),
        'raw_ppg': 'rawFrameRef',
        'unused_v24_byte_72': 'not interpreted',
      },
      'forbiddenFields': ['gravity', 'heart_rate', 'spo2', 'skin_temperature', 'sleep_stage'],
    };
  }
  if (family == 'whoop5') {
    final sample = parseGen5Historical(frames[index].inner);
    Map<String, dynamic>? diagnostics;
    if (sample is Gen5HistorySample) {
      // Decoding a candidate field is NOT exposing it. -5000 is the
      // unavailable sentinel and must abstain (skinTempCOrNull == null).
      diagnostics = {
        'skinTempCOrNull': sample.skinTempCOrNull,
        'skinTempSentinelAbstained': !sample.skinTempAvailable,
        'spo2CandidateRaw': sample.spo2CandidateRaw,
        'statusWordsRaw': [
          sample.statusWord,
          sample.statusWord1,
          sample.statusWord2,
        ],
        'sleepStateByteRaw': sample.sleepStateByte,
        'r22Writes': caseData['r22Writes'] == true,
      };
    }
    return {
      ...base,
      'kind': 'w5_raw_diagnostics',
      'fields': {'timestamp_bytes': view['innerHex'].substring(14, 22), 'raw': 'rawFrameRef'},
      if (diagnostics != null) 'diagnostics': diagnostics,
      'forbiddenFields': [
        'spo2',
        'skin_temperature',
        'sleep_stage',
        'respiration',
        'r22_configuration_write',
      ],
    };
  }
  if (family == 'whoop4' && packetType == 0x2F) {
    final parsed = parseR24(frames[index].inner);
    return {
      ...base,
      'kind': 'w4_historical_diagnostics',
      'decoded': parsed?.toMap(),
      'fields': {'unused_v24_byte_72': 'not interpreted'},
      'exposureAllowed': false,
      'note': 'Raw diagnostic decode only; not a validated HR/RHR trend.',
    };
  }
  return {...base, 'kind': 'raw_preservation_only'};
}

void _fail(String message) {
  stderr.writeln('FAIL: $message');
  exitCode = 1;
}

void main(List<String> args) {
  final options = <String, String>{};
  for (var i = 0; i < args.length; i++) {
    if (args[i].startsWith('--') && i + 1 < args.length) {
      options[args[i].substring(2)] = args[++i];
    }
  }
  final root = options['root'] ?? Directory.current.path;
  final fixturesDir = Directory(options['fixtures'] ?? '$root/fixtures/synthetic');
  final goldensDir = Directory(options['goldens'] ?? '$root/fixtures/goldens');
  final parityPath = options['parity'] ?? '$root/protocol/decode_parity_cases.json';
  final reportPath = options['out'];

  if (!fixturesDir.existsSync() || !goldensDir.existsSync()) {
    _fail('missing fixtures/ or goldens/ directory');
    return;
  }

  final fixtureFiles = fixturesDir
      .listSync()
      .whereType<File>()
      .where((f) => f.path.endsWith('.json') && !f.path.endsWith('.meta.json'))
      .toList()
    ..sort((a, b) => a.path.compareTo(b.path));

  final report = <String, dynamic>{
    'schema': 'openstrap-replay-report/v1',
    'decoderVersion': decoderVersion,
    'hardware': 'none',
    'fixtures': <dynamic>[],
    'parity': <String, dynamic>{},
  };

  for (final fixtureFile in fixtureFiles) {
    final caseData = _readJson(fixtureFile.path);
    final id = caseData['id'] as String;
    final goldensPath = goldensDir.path;
    final goldenPath = '$goldensPath/$id.golden.json';
    if (!File(goldenPath).existsSync()) {
      _fail('$id: missing golden $goldenPath');
      continue;
    }
    final golden = _readJson(goldenPath)['expected'] as Map<String, dynamic>;
    final profile = caseData['profile'] == 'gen5' ? BandProfile.gen5 : BandProfile.gen4;
    final giveUp = caseData['giveUpTruncatedFrames'] == true;
    final reassemblers = <String, FrameReassembler>{};
    final frames = <Frame>[];

    for (final rawNotification in caseData['notifications'] as List<dynamic>) {
      final notification = rawNotification as Map<String, dynamic>;
      final characteristic = notification['characteristic'] as String;
      final capacity = notification['attPayloadCapacity'] as int;
      if (capacity < 20 || capacity > 247) {
        _fail('$id: implausible ATT payload capacity $capacity');
      }
      final chunk = hexToBytes(notification['hex'] as String);
      if (chunk.length > capacity) {
        _fail('$id: notification length ${chunk.length} exceeds ATT capacity $capacity');
      }
      final reassembler = reassemblers.putIfAbsent(
        characteristic,
        () => FrameReassembler(profile: profile, giveUpTruncatedFrames: giveUp),
      );
      frames.addAll(reassembler.feed(chunk));
    }

    final stats = <String, int>{
      'resyncs': reassemblers.values.fold(0, (sum, r) => sum + r.resyncs),
      'lostFrames': reassemblers.values.fold(0, (sum, r) => sum + r.lostFrames),
      'truncations': reassemblers.values.fold(0, (sum, r) => sum + r.truncations),
    };
    final frameViews = <Map<String, dynamic>>[
      for (var i = 0; i < frames.length; i++) _frameView(frames[i], i, id),
    ];
    final actual = {'frames': frameViews, 'stats': stats};
    final diff = _diff(actual, golden, id);
    if (diff != null) _fail('$id: golden mismatch: $diff');

    (report['fixtures'] as List<dynamic>).add({
      'id': id,
      'family': caseData['family'],
      'frames': frameViews.length,
      'validFrames': frameViews.where((v) => v['valid'] == true).length,
      'stats': stats,
      'samples': [
        for (var i = 0; i < frames.length; i++)
          _canonicalSample(
            caseData['family'] as String,
            id,
            frameViews[i],
            caseData,
            frames,
            i,
          ),
      ],
      'golden': 'match',
    });
  }

  // Frozen public oracle: every one of the 2,934 (kind, frame, output) triples
  // goes through the same decoders the app calls.
  final parityCases = _readJsonList(parityPath);
  var parityMatched = 0;
  final parityFailures = <String>[];
  for (var i = 0; i < parityCases.length; i++) {
    final c = parityCases[i] as Map<String, dynamic>;
    final actual = _decodeParityKind(c['kind'] as String, c['hex'] as String);
    final diff = _diff(actual, c['out'], 'case[$i](${c['kind']})');
    if (diff == null) {
      parityMatched++;
    } else if (parityFailures.length < 10) {
      parityFailures.add(diff);
    }
  }
  report['parity'] = {
    'source': parityPath,
    'cases': parityCases.length,
    'matched': parityMatched,
    'failures': parityFailures,
  };
  if (parityMatched != parityCases.length) {
    _fail('parity matched $parityMatched/${parityCases.length}: ${parityFailures.join('; ')}');
  }

  final reportJson = json.encode(report);
  if (reportPath != null) {
    File(reportPath).writeAsStringSync('$reportJson\n');
  }
  if (exitCode != 0) return; // a fixture failure must never print PASS
  stdout.writeln(
    'PASS: ${fixtureFiles.length} synthetic cases, $parityMatched/${parityCases.length} frozen-oracle cases; hardware=none',
  );
}
