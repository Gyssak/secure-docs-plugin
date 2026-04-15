<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

class SecureDocuments
{
    public function __construct()
    {
        add_action('init', [$this, 'register_cpt']);
        add_action('add_meta_boxes', [$this, 'add_meta_box']);
        add_action('wp_ajax_generate_secure_link', [$this, 'generate_link']);
        add_action('template_redirect', [$this, 'handle_access']);
    }

    public function register_cpt(): void
    {
    }

    public function add_meta_box(): void
    {
    }

    public function generate_link(): void
    {
    }

    public function handle_access(): void
    {
    }
}

new SecureDocuments();