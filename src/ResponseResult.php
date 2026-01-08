<?php

namespace Klsoft\KeycloakClient;

use stdClass;

final class ResponseResult
{
    /**
     * @param int $responseStatusCode
     * @param stdClass $data
     */
    public function __construct(
        public readonly int      $responseStatusCode,
        public readonly stdClass $data)
    {
    }
}
