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

    public function register_cpt(): void {
        register_post_type('shared_document', [
            'label' => 'Документи',
            'labels' => [
                'name' => 'Документи',
                'singular_name' => 'Документ',
                'add_new' => 'Додати документ',
                'add_new_item' => 'Додати новий документ',
                'edit_item' => 'Редагувати документ'
            ],
            'public' => false,
            'has_archive' => false,
            'publicly_queryable' => false,
            'show_ui' => true,
            'show_in_menu' => true,
            'supports' => ['title', 'editor']
        ]);
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