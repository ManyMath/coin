import 'package:unorm_dart/unorm_dart.dart' as unorm;

import 'langs/cs.dart';
import 'langs/en.dart';
import 'langs/es.dart';
import 'langs/fr.dart';
import 'langs/it.dart';
import 'langs/jp.dart';
import 'langs/ko.dart';
import 'langs/pt.dart';
import 'langs/zh_s.dart';
import 'langs/zh_t.dart';

class PolyseedLang {
  final String name;
  final String nameEnglish;
  final String separator;
  final bool isSorted;
  final bool hasPrefix;
  final bool hasAccents;
  final bool compose;
  final List<String> words;

  const PolyseedLang({
    required this.name,
    required this.nameEnglish,
    required this.separator,
    required this.isSorted,
    required this.hasPrefix,
    required this.hasAccents,
    required this.compose,
    required this.words,
  });

  static const List<PolyseedLang> languages = [
    csLang,
    enLang,
    esLang,
    frLang,
    itLang,
    jpLang,
    koLang,
    ptLang,
    zhsLang,
    zhtLang,
  ];

  /// Find the language whose entire wordlist covers every word in [phrase].
  ///
  /// Throws [FormatException] if no language matches, or if more than one does.
  static PolyseedLang getByPhrase(String phrase) {
    PolyseedLang? matched;
    for (final language in languages) {
      final words =
          language.normalizeSeparator(phrase).split(language.separator);
      if (words.every((word) => language.findWord(word) >= 0)) {
        if (matched != null) throw const FormatException('Ambiguous language');
        matched = language;
      }
    }
    if (matched == null) throw const FormatException('Unknown language');
    return matched;
  }

  /// Return the 0-based index of [word] in this language's wordlist, or -1.
  int findWord(String word) {
    if (hasPrefix) return _prefixMatchSearch(word);
    if (hasAccents) {
      // NFKD-normalise both sides so accented input matches accented wordlist.
      final target = unorm.nfkd(word);
      return words.indexWhere((w) => unorm.nfkd(w) == target);
    }
    // NFC-normalise both sides so NFD-encoded wordlists (e.g. Japanese BIP-39,
    // which stores ぶ as ふ + combining dakuten) still match NFC user input.
    final target = unorm.nfc(word);
    return words.indexWhere((w) => unorm.nfc(w) == target);
  }

  /// Prefix-match search (used when [hasPrefix] is true, e.g. English).
  ///
  /// A word matches if its first [prefixLen] codepoints match the candidate.
  /// Words shorter than [prefixLen] must match exactly. Returns -1 on
  /// ambiguity (two words share the same prefix).
  int _prefixMatchSearch(String word) {
    const prefixLen = 4;

    // Strip combining marks to make the comparison accent-insensitive.
    String stripAccents(String s) => unorm
        .nfkd(s)
        .runes
        .where((r) => r < 128) // keep only ASCII codepoints
        .map(String.fromCharCode)
        .join();

    final targetWord = hasAccents ? stripAccents(word) : word;
    final targetChars = targetWord.runes.toList();

    int? matchIdx;
    for (var i = 0; i < words.length; i++) {
      final langWord = hasAccents ? stripAccents(words[i]) : words[i];
      final langChars = langWord.runes.toList();

      var matches = true;
      var count = 0;
      for (var j = 0;
          j < prefixLen && j < targetChars.length && j < langChars.length;
          j++) {
        if (targetChars[j] != langChars[j]) {
          matches = false;
          break;
        }
        count++;
      }
      // If we couldn't compare all [prefixLen] chars (short word), require
      // that neither string has more chars  -  i.e. exact match for short words.
      if (count < prefixLen) {
        if (count < targetChars.length || count < langChars.length) {
          matches = false;
        }
      }

      if (matches) {
        if (matchIdx != null) return -1; // ambiguous prefix
        matchIdx = i;
      }
    }
    return matchIdx ?? -1;
  }

  /// Decode [phrase] into a list of 0-based word indices (-1 = unknown word).
  List<int> decodePhrase(String phrase) => normalizeSeparator(phrase)
      .split(separator)
      .map(findWord)
      .toList();

  /// Encode coefficient indices back to a mnemonic phrase.
  String encodePhrase(List<int> coefficients) =>
      coefficients.map((e) => words[e]).join(separator);

  /// Replace ASCII space with the language's separator for user convenience
  /// (e.g. Japanese uses ideographic space U+3000).
  String normalizeSeparator(String phrase) =>
      separator != '\u0020' ? phrase.replaceAll('\u0020', separator) : phrase;
}
