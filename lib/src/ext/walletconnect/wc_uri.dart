/// WalletConnect `wc:` URI parsing/serialization (EIP-1328), v1 and v2.
///
/// v1: `wc:{topic}@1?bridge={urlencoded}&key={hex}`
/// v2: `wc:{topic}@2?relay-protocol={p}&symKey={hex}`
class WcUri {
  final String topic;
  final int version;

  // v1 fields
  final String? bridge;
  final String? key;

  // v2 fields
  final String? relayProtocol;
  final String? symKey;

  const WcUri({
    required this.topic,
    required this.version,
    this.bridge,
    this.key,
    this.relayProtocol,
    this.symKey,
  });

  static WcUri parse(String uri) {
    if (!uri.startsWith('wc:')) {
      throw FormatException('not a wc: URI: $uri');
    }
    final body = uri.substring(3);
    final qIdx = body.indexOf('?');
    final pathPart = qIdx >= 0 ? body.substring(0, qIdx) : body;
    final query = qIdx >= 0 ? body.substring(qIdx + 1) : '';

    final at = pathPart.indexOf('@');
    if (at < 0) {
      throw FormatException('missing version in wc: URI: $uri');
    }
    final topic = pathPart.substring(0, at);
    final version = int.parse(pathPart.substring(at + 1));

    final params = <String, String>{};
    if (query.isNotEmpty) {
      for (final pair in query.split('&')) {
        final eq = pair.indexOf('=');
        if (eq < 0) continue;
        final k = Uri.decodeComponent(pair.substring(0, eq));
        final v = Uri.decodeComponent(pair.substring(eq + 1));
        params[k] = v;
      }
    }

    if (version == 1) {
      return WcUri(
        topic: topic,
        version: 1,
        bridge: params['bridge'],
        key: params['key'],
      );
    }
    return WcUri(
      topic: topic,
      version: version,
      relayProtocol: params['relay-protocol'],
      symKey: params['symKey'],
    );
  }

  String serialize() {
    if (version == 1) {
      final encodedBridge = Uri.encodeComponent(bridge ?? '');
      return 'wc:$topic@1?bridge=$encodedBridge&key=$key';
    }
    return 'wc:$topic@$version?relay-protocol=$relayProtocol&symKey=$symKey';
  }

  @override
  String toString() => serialize();
}

/// A link-mode (deep-link) message: the [topic] it targets and the out-of-band
/// [envelope] (a type-2 base64url envelope) it carries.
class WcLinkModeMessage {
  final String topic;
  final String envelope;
  const WcLinkModeMessage({required this.topic, required this.envelope});
}

/// Build a link-mode deep link carrying an out-of-band [envelope]:
/// `{universalLink}?wc_ev={envelope}&topic={topic}` (reown `getLinkModeURL`).
String wcLinkModeUrl(String universalLink, String topic, String envelope) =>
    '$universalLink?wc_ev=${Uri.encodeQueryComponent(envelope)}'
    '&topic=${Uri.encodeQueryComponent(topic)}';

/// Parse the `topic` + `wc_ev` (envelope) params out of a link-mode [url].
WcLinkModeMessage wcParseLinkModeUrl(String url) {
  final uri = Uri.parse(url);
  final envelope = uri.queryParameters['wc_ev'];
  final topic = uri.queryParameters['topic'];
  if (envelope == null || topic == null) {
    throw FormatException('not a link-mode url (missing wc_ev/topic): $url');
  }
  return WcLinkModeMessage(topic: topic, envelope: envelope);
}
