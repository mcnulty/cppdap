// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "content_stream.h"

#include "dap/io.h"

#include <string.h>   // strlen
#include <algorithm>  // std::min

namespace dap {

////////////////////////////////////////////////////////////////////////////////
// ContentReader
////////////////////////////////////////////////////////////////////////////////
ContentReader::ContentReader(const std::shared_ptr<Reader>& reader)
    : reader(reader) {}

ContentReader& ContentReader::operator=(ContentReader&& rhs) noexcept {
  buf = std::move(rhs.buf);
  reader = std::move(rhs.reader);
  return *this;
}

bool ContentReader::isOpen() {
  return reader ? reader->isOpen() : false;
}

void ContentReader::close() {
  if (reader) {
    reader->close();
  }
}

// Limit message sizes to 10 MB to prevent DoS issues
#define MAX_CONTENT_LENGTH (100000000)

std::string ContentReader::read() {
  // Currently, a DAP message is encoded like:
  // Content-Length: 2\r\n
  // \r\n
  // {}
  auto contentLengthResult = readContentLength();
  if (!contentLengthResult.first) {
    return invalidMsg();
  }

  auto len = contentLengthResult.second;

  // Read message
  std::string out;
  out.reserve(len);

  // Start with any extra data read when parsing the header
  while (out.size() < len && !buf.empty()) {
    uint8_t c = buf.front();
    out.push_back(static_cast<char>(c));
    buf.pop_front();
  }

  if (!readContent(out, len)) {
    return invalidMsg();
  }

  return out;
}

std::string ContentReader::invalidMsg() {
  this->close();
  return "";
}

// Given a max content length of 10 MB, the Content-Length header field
// has a known max length:
// (the length of "Content-Length") +
// (the length of the max content length value) +
// (the length of "\r\n")*2
#define MAX_HEADER_LENGTH (16 + 9 + 2 + 2)

static inline std::pair<bool, size_t> invalidHeader() {
  return std::make_tuple(false, 0);
}

std::pair<bool, size_t> ContentReader::readContentLength() {
  std::string header;
  header.reserve(MAX_HEADER_LENGTH);

  bool headerComplete = false;
  while (!headerComplete && header.size() <= MAX_HEADER_LENGTH) {
    uint8_t localBuf[MAX_HEADER_LENGTH];

    size_t numGot;
    if (buf.size() > 0) {
      numGot = buf.size();
      for (size_t i = 0; i < MAX_HEADER_LENGTH && !buf.empty(); i++) {
        localBuf[i] = buf.front();
        buf.pop_front();
      }
    } else {
      numGot = reader->read(localBuf, MAX_HEADER_LENGTH);
      if (numGot == 0) {
        // The message was terminated early
        return invalidHeader();
      }
    }

    for (size_t i = 0; i < numGot; i++) {
      if (headerComplete) {
        buf.push_back(localBuf[i]);
        continue;
      }

      header.push_back(static_cast<char>(localBuf[i]));
      if (header.size() >= 4 && header.at(header.size() - 4) == '\r' &&
          header.at(header.size() - 3) == '\n' &&
          header.at(header.size() - 2) == '\r' &&
          header.at(header.size() - 1) == '\n') {
        headerComplete = true;
      }
    }
  }

  if (!headerComplete) {
    // The header field was too long
    return invalidHeader();
  }

  auto colon = header.find_first_of(':');
  if (colon == std::string::npos) {
    return invalidHeader();
  }
  if (colon == header.size() - 1) {
    // No value was included
    return invalidHeader();
  }

  // Don't trim the name as trailing whitespace has led to vulnerabilities in
  // HTTP parsers
  auto name = header.substr(0, colon);
  if (name != "Content-Length") {
    return invalidHeader();
  }

  auto value = header.substr(colon + 1, (header.size() - 4 - name.size() - 1));

  // Technically, there should be just one space after the colon but the
  // previous version allowed a tab character after the colon so allow that too
  value.erase(0, value.find_first_not_of(" \t"));

  size_t len = 0;
  for (char c : value) {
    switch (c) {
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
        len *= 10;
        len += size_t(c) - size_t('0');
        break;
      default:
        return invalidHeader();
    }
  }

  if (len > MAX_CONTENT_LENGTH) {
    return invalidHeader();
  }

  return std::make_pair(true, len);
}

bool ContentReader::readContent(std::string& output, size_t len) {
  while (output.size() < len) {
    uint8_t buf[256];
    auto remaining = len - output.size();
    auto numWant = std::min(sizeof(buf), remaining);
    auto numGot = reader->read(buf, numWant);
    if (numGot == 0) {
      return false;
    }

    for (size_t i = 0; i < numGot; i++) {
      output.push_back(static_cast<char>(buf[i]));
    }
  }

  return true;
}

////////////////////////////////////////////////////////////////////////////////
// ContentWriter
////////////////////////////////////////////////////////////////////////////////
ContentWriter::ContentWriter(const std::shared_ptr<Writer>& rhs)
    : writer(rhs) {}

ContentWriter& ContentWriter::operator=(ContentWriter&& rhs) noexcept {
  writer = std::move(rhs.writer);
  return *this;
}

bool ContentWriter::isOpen() {
  return writer ? writer->isOpen() : false;
}

void ContentWriter::close() {
  if (writer) {
    writer->close();
  }
}

bool ContentWriter::write(const std::string& msg) const {
  auto header =
      std::string("Content-Length: ") + std::to_string(msg.size()) + "\r\n\r\n";
  return writer->write(header.data(), header.size()) &&
         writer->write(msg.data(), msg.size());
}

}  // namespace dap
